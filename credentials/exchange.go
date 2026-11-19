package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ExchangeConfig configures an ExchangeClient.
type ExchangeConfig struct {
	// Issuer is the public address of NICE.
	Issuer string
	// ClientID and ClientSecret are those of the confidential service client of the backend: the actor of every
	// exchange. The secret is sent to NICE only.
	ClientID     string
	ClientSecret string `json:"-"`
	// MaxCached is the most tokens kept, the least recently used going first; default 2000.
	MaxCached int
	// Margin is how long before its expiry a kept token is exchanged again; default 60 seconds.
	Margin time.Duration
	// HTTP talks to NICE and, in DoAs, to the services; default a client with a 30 second timeout. The calls to
	// NICE go through a copy of it that follows no redirect.
	HTTP *http.Client
	// AllowInsecureHTTP accepts a plain http address of NICE or of a service that is not loopback; see
	// Config.AllowInsecureHTTP.
	AllowInsecureHTTP bool
	Log               *slog.Logger
	// Now is for tests.
	Now func() time.Time
}

// ExchangeClient is the exchange mode for the backend of a service: it trades the access token a user's request
// brought (the subject token) for a token to call another service, or the NICE API, on behalf of that user
// (RFC 8693). The backend never holds a refresh token. Tokens are kept per (subject token, organization, project,
// audience) and are exchanged only when none is kept that is still good. Calls for one key share one exchange; calls
// for different keys never wait for each other. A refusal of NICE (invalid_grant, invalid_client,
// unauthorized_client) is returned as a GrantError and not retried.
//
// The client reads the subject token without verifying it, so what it reads never decides whose token is handed
// out: a kept token is found by the subject token itself. A forged token that names another user is a subject
// token of its own, goes to NICE, and is refused there. The backend still verifies the token of every request
// before it serves it.
type ExchangeClient struct {
	cfg ExchangeConfig
	// nice is cfg.HTTP for the calls to NICE: it follows no redirect.
	nice *http.Client

	mu      sync.Mutex
	entries map[exchangeKey]*exchangeEntry
}

// exchangeKey is the key of a kept token. token is the SHA-256 of the subject token: the other fields come from
// claims nobody verified here, so they alone must not find the token of a user.
type exchangeKey struct {
	token                           [sha256.Size]byte
	subject, org, project, audience string
}

type exchangeEntry struct {
	tok     Token
	hasTok  bool
	lastUse time.Time
	flight  *flight
}

// NewExchange builds an ExchangeClient.
func NewExchange(cfg ExchangeConfig) (*ExchangeClient, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("niceauth: Issuer, ClientID and ClientSecret are required for the exchange")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if _, err := checkURL("Issuer", cfg.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if cfg.MaxCached <= 0 {
		cfg.MaxCached = KindBFF.limits().MaxCached
	}
	if cfg.Margin <= 0 {
		cfg.Margin = time.Minute
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &ExchangeClient{cfg: cfg, nice: noRedirect(cfg.HTTP), entries: map[exchangeKey]*exchangeEntry{}}, nil
}

// Len is how many tokens are kept.
func (x *ExchangeClient) Len() int { x.mu.Lock(); defer x.mu.Unlock(); return len(x.entries) }

// subjectClaims are what the client reads from a subject token, without verifying it: the backend verified it
// when the request came in, and NICE verifies it again on the exchange.
type subjectClaims struct {
	Subject string `json:"sub"`
	OrgID   string `json:"nice_org_id"`
	Project string `json:"prj"`
	Expiry  int64  `json:"exp"`
}

func readSubject(token string) (subjectClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return subjectClaims{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return subjectClaims{}, false
	}
	var c subjectClaims
	if json.Unmarshal(b, &c) != nil || c.Subject == "" || c.Expiry == 0 {
		return subjectClaims{}, false
	}
	return c, true
}

// keyOf is the cache key of key for subjectToken: what NICE would decide when key leaves the organization or
// project out, and the subject token itself.
func keyOf(subjectToken string, sc subjectClaims, key Key) exchangeKey {
	k := exchangeKey{token: sha256.Sum256([]byte(subjectToken)), subject: sc.Subject, org: key.Org, project: key.Project, audience: key.Audience}
	if k.audience == "" {
		k.audience = "nice"
	}
	if k.org == "" {
		k.org = sc.OrgID
	}
	switch {
	case k.audience == "nice":
		k.project = ""
	case k.project == "" && k.org == sc.OrgID:
		k.project = sc.Project
	}
	return k
}

func exchangeScope(key Key) string {
	aud := key.Audience
	if aud == "" {
		aud = "nice"
	}
	s := "nice:aud:" + aud
	if key.Org != "" {
		s += " nice:org:" + key.Org
	}
	if key.Project != "" {
		s += " nice:prj:" + key.Project
	}
	return s
}

// Token returns a token for key on behalf of the user of subjectToken: the one kept for this subject token if it is
// still good for at least Margin, otherwise a new exchange. A renewed subject token exchanges again.
func (x *ExchangeClient) Token(ctx context.Context, subjectToken string, key Key) (Token, error) {
	sc, ok := readSubject(subjectToken)
	if !ok {
		return Token{}, errors.New("niceauth: the subject token is not an access token of NICE")
	}
	subjectExp := time.Unix(sc.Expiry, 0)
	if !x.cfg.Now().Before(subjectExp) {
		return Token{}, errors.New("niceauth: the subject token has expired")
	}
	k := keyOf(subjectToken, sc, key)
	x.mu.Lock()
	e := x.touchLocked(k)
	if e.hasTok && x.usable(e.tok, subjectExp) {
		tok := e.tok
		x.mu.Unlock()
		return tok, nil
	}
	if f := e.flight; f != nil {
		x.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return Token{}, ctx.Err()
		}
		if f.err != nil {
			return Token{}, f.err
		}
		return f.tok, nil
	}
	f := &flight{done: make(chan struct{})}
	e.flight = f
	x.mu.Unlock()

	tok, _, err := x.post(detach(ctx), subjectToken, key)
	x.mu.Lock()
	e.flight = nil
	if err == nil {
		e.tok, e.hasTok = tok, true
	}
	f.tok, f.err = tok, err
	x.mu.Unlock()
	close(f.done)
	return tok, err
}

func (x *ExchangeClient) usable(tok Token, subjectExp time.Time) bool {
	return x.cfg.Now().Before(tok.ExpiresAt.Add(-x.cfg.Margin)) && !tok.ExpiresAt.After(subjectExp)
}

func (x *ExchangeClient) post(ctx context.Context, subjectToken string, key Key) (Token, string, error) {
	return postToken(ctx, x.nice, x.cfg.Issuer, x.cfg.Now, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {x.cfg.ClientID}, "client_secret": {x.cfg.ClientSecret},
		"subject_token": {subjectToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "scope": {exchangeScope(key)}})
}

// touchLocked finds or creates the entry of k and keeps the cache within MaxCached.
func (x *ExchangeClient) touchLocked(k exchangeKey) *exchangeEntry {
	e, ok := x.entries[k]
	if !ok {
		e = &exchangeEntry{}
		x.entries[k] = e
		for len(x.entries) > x.cfg.MaxCached {
			var oldest exchangeKey
			var found bool
			for ok2, oe := range x.entries {
				if oe == e || oe.flight != nil {
					continue
				}
				if !found || oe.lastUse.Before(x.entries[oldest].lastUse) {
					oldest, found = ok2, true
				}
			}
			if !found {
				break
			}
			delete(x.entries, oldest)
		}
	}
	e.lastUse = x.cfg.Now()
	return e
}

// invalidate drops the token kept for k if it is still tok.
func (x *ExchangeClient) invalidate(k exchangeKey, tok Token) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e, ok := x.entries[k]; ok && e.hasTok && e.tok.Access == tok.Access {
		e.hasTok = false
	}
}

// DoAs sends req to a service with a token for key on behalf of the user of subjectToken. A service that answers
// 401 because the token is stale or expired gets one new exchange and the request once more; the second answer is
// returned whatever it is. A request with a body is only sent again if req.GetBody is set.
//
// The token goes to the host req names, so name only the service of key. A plain http address that is not loopback
// is refused before anything is exchanged, unless ExchangeConfig.AllowInsecureHTTP is set. Config.HTTP follows
// redirects as it is set to; net/http drops the token on a redirect to another domain, but not to a subdomain.
func (x *ExchangeClient) DoAs(ctx context.Context, subjectToken string, key Key, req *http.Request) (*http.Response, error) {
	if err := checkParsed("the request address", req.URL, x.cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		tok, err := x.Token(ctx, subjectToken, key)
		if err != nil {
			return nil, err
		}
		r := req.Clone(ctx)
		r.Header.Set("Authorization", "Bearer "+tok.Access)
		if attempt > 0 && req.Body != nil && req.Body != http.NoBody {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
		resp, err := x.cfg.HTTP.Do(r)
		if err != nil || resp.StatusCode != http.StatusUnauthorized || attempt > 0 || !staleChallenge(resp) {
			return resp, err
		}
		if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
			return resp, nil // cannot send it again
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		sc, _ := readSubject(subjectToken)
		x.invalidate(keyOf(subjectToken, sc, key), tok)
	}
}
