package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrStateMismatch is returned for a callback whose state is unknown, expired,
// already used, or was made for another local session. The token is not kept.
var ErrStateMismatch = errors.New("niceauth: the callback does not belong to this session")

// ConnectRequest starts connecting a local user to a NICE account, the way an
// application lets a user connect a provider: the user is signed in to the
// application already, and signs in to NICE only for what needs it.
type ConnectRequest struct {
	// Subject is the stable ID of the local user; the tokens are kept under it.
	Subject string
	// Session is the ID of the local session that starts the connection. The callback must come
	// from the same session, so nobody can link their NICE account to someone else's user.
	Session string
	// RedirectURI is the callback of the application registered with the OAuth client.
	RedirectURI string
	// Org, Audience and Project ask for the first token; each is optional. Another service
	// later needs no new sign-in: Token asks for it with the refresh token.
	Org, Audience, Project string
}

// Pending is a connection that was started and not yet completed.
type Pending struct {
	Verifier    string    `json:"verifier"`
	Subject     string    `json:"subject"`
	Session     string    `json:"session"`
	RedirectURI string    `json:"redirect_uri"`
	Audience    string    `json:"audience"`
	Project     string    `json:"project"`
	Expires     time.Time `json:"expires"`
}

// PendingStore keeps the connections that were started. A Store may implement
// it when the application runs several processes, so the callback can reach another one
// than the one that started the connection; otherwise they are kept in memory.
type PendingStore interface {
	SavePending(ctx context.Context, state string, p Pending) error
	// TakePending returns the connection for state and removes it: a state is used once.
	TakePending(ctx context.Context, state string) (Pending, bool, error)
}

const pendingTTL = 10 * time.Minute

type memoryPending struct {
	mu sync.Mutex
	m  map[string]Pending
}

func (p *memoryPending) SavePending(_ context.Context, state string, v Pending) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]Pending{}
	}
	p.m[state] = v
	return nil
}

func (p *memoryPending) TakePending(_ context.Context, state string) (Pending, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[state]
	delete(p.m, state)
	return v, ok, nil
}

func (m *MemoryStore) SavePending(ctx context.Context, state string, p Pending) error {
	return m.pend.SavePending(ctx, state, p)
}

func (m *MemoryStore) TakePending(ctx context.Context, state string) (Pending, bool, error) {
	return m.pend.TakePending(ctx, state)
}

func (f *FileStore) SavePending(_ context.Context, state string, p Pending) error {
	b, _ := json.Marshal(p)
	return f.write(f.path("pending", state), b)
}

func (f *FileStore) TakePending(_ context.Context, state string) (Pending, bool, error) {
	path := f.path("pending", state)
	taken := path + ".taken"
	if err := os.Rename(path, taken); err != nil {
		return Pending{}, false, nil // unknown, or taken by another process a moment ago
	}
	defer func() { _ = os.Remove(taken) }()
	b, err := os.ReadFile(taken)
	if err != nil {
		return Pending{}, false, err
	}
	var p Pending
	if json.Unmarshal(b, &p) != nil {
		return Pending{}, false, nil
	}
	return p, true, nil
}

func (c *Client) pendingStore() PendingStore {
	if ps, ok := c.cfg.Store.(PendingStore); ok {
		return ps
	}
	return &c.pending
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthorizeURL returns the address to send the user's browser to. The state and
// the PKCE verifier are kept until the callback.
func (c *Client) AuthorizeURL(ctx context.Context, req ConnectRequest) (string, error) {
	if req.Subject == "" || req.Session == "" || req.RedirectURI == "" {
		return "", errors.New("niceauth: Subject, Session and RedirectURI are required")
	}
	if c.isServiceAccount() {
		return "", errors.New("niceauth: a Service Account does not connect through a browser")
	}
	verifier, err := randomURLSafe(48)
	if err != nil {
		return "", err
	}
	state, err := randomURLSafe(24)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	scopes := append([]string(nil), c.cfg.BaseScopes...)
	if req.Org != "" {
		scopes = append(scopes, "nice:org:"+req.Org)
	}
	if req.Audience != "" {
		scopes = append(scopes, "nice:aud:"+req.Audience)
	}
	if req.Project != "" {
		scopes = append(scopes, "nice:prj:"+req.Project)
	}
	p := Pending{Verifier: verifier, Subject: req.Subject, Session: req.Session, RedirectURI: req.RedirectURI,
		Audience: req.Audience, Project: req.Project, Expires: c.cfg.Now().Add(pendingTTL)}
	if err := c.pendingStore().SavePending(ctx, state, p); err != nil {
		return "", err
	}
	q := url.Values{"client_id": {c.cfg.ClientID}, "redirect_uri": {req.RedirectURI}, "response_type": {"code"}, "scope": {strings.Join(scopes, " ")},
		"state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	return c.cfg.Issuer + "/oauth/authorize?" + q.Encode(), nil
}

// Connection is a completed connect.
type Connection struct {
	// Subject is the local user the tokens are kept for.
	Subject string
	// NiceSubject is the NICE account that was connected (usr_...), read from the token. The
	// application keeps one NICE account for one local user: it must refuse a NICE account
	// that is already linked to another.
	NiceSubject string
}

// HandleCallback completes a connection from the query of the callback request.
// session is the ID of the local session that received it; it must be the one
// that started the connection.
func (c *Client) HandleCallback(ctx context.Context, session string, query url.Values) (Connection, error) {
	state := query.Get("state")
	if state == "" {
		return Connection{}, ErrStateMismatch
	}
	p, ok, err := c.pendingStore().TakePending(ctx, state)
	if err != nil {
		return Connection{}, err
	}
	if !ok || p.Session != session || c.cfg.Now().After(p.Expires) {
		return Connection{}, ErrStateMismatch
	}
	if e := query.Get("error"); e != "" {
		return Connection{}, &GrantError{Status: http.StatusBadRequest, Code: e, Description: query.Get("error_description")}
	}
	code := query.Get("code")
	if code == "" {
		return Connection{}, &GrantError{Status: http.StatusBadRequest, Code: "invalid_request", Description: "the callback has no code"}
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.RedirectURI}, "client_id": {c.cfg.ClientID},
		"code_verifier": {p.Verifier}}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	tok, refresh, err := c.exchange(ctx, form)
	if err != nil {
		return Connection{}, err
	}
	if refresh == "" {
		return Connection{}, &GrantError{Status: http.StatusBadRequest, Code: "invalid_scope", Description: "NICE gave no refresh token; the client must be allowed offline_access"}
	}
	if err := c.saveRefresh(ctx, p.Subject, refresh); err != nil {
		return Connection{}, err
	}
	key := c.normalize(Key{Subject: p.Subject, Audience: p.Audience, Project: p.Project})
	_ = c.cfg.Store.SaveToken(ctx, key, tok)
	c.Reset(p.Subject)
	c.mu.Lock()
	e := c.touchLocked(key, c.cfg.Now())
	e.tok, e.hasTok, e.lastErr, e.noRenew = tok, true, nil, false
	e.refreshAt = tok.IssuedAt.Add(c.cfg.RefreshAfter + time.Duration(c.cfg.Rand()*float64(c.cfg.Jitter)))
	c.mu.Unlock()
	return Connection{Subject: p.Subject, NiceSubject: subjectOf(tok.Access)}, nil
}

// subjectOf reads sub from the payload of a JWT without verifying it; it only names the account.
func subjectOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Sub
}

// Connected reports whether subject has a session with NICE.
func (c *Client) Connected(ctx context.Context, subject string) bool {
	c.mu.Lock()
	dead := c.dead[subject]
	c.mu.Unlock()
	if dead != nil {
		return false
	}
	_, err := c.cfg.Store.RefreshToken(ctx, subject)
	return err == nil
}

// Disconnect revokes the refresh token of subject at NICE and forgets the
// session. If NICE cannot be reached the session is kept and the error returned,
// so the application can try again; a user must not look disconnected while the token still works.
func (c *Client) Disconnect(ctx context.Context, subject string) error {
	rt, err := c.cfg.Store.RefreshToken(ctx, subject)
	if errors.Is(err, ErrNotConnected) {
		c.Forget(subject)
		return nil
	}
	if err != nil {
		return err
	}
	form := url.Values{"token": {rt}, "token_type_hint": {"refresh_token"}, "client_id": {c.cfg.ClientID}}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Issuer+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.nice.Do(req)
	if err != nil {
		return &TemporaryError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &TemporaryError{Err: fmt.Errorf("revocation answered %d", resp.StatusCode)}
	}
	if isRedirect(resp.StatusCode) {
		// Nothing was revoked: the session is kept, as when NICE cannot be reached.
		return fmt.Errorf("niceauth: revocation answered with a redirect to %s; nothing was sent there, check Issuer", redirectTarget(resp))
	}
	if err := c.cfg.Store.DeleteSubject(ctx, subject); err != nil {
		return err
	}
	c.Forget(subject)
	return nil
}
