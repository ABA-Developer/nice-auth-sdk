package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// subjectLock serializes the use of the refresh token of one subject inside this process.
func (c *Client) subjectLock(subject string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.locks[subject]
	if !ok {
		l = &sync.Mutex{}
		c.locks[subject] = l
	}
	return l
}

// scopeOf is the scope of a grant for key. A refresh names the base scopes, since NICE replaces the scopes
// of the grant with those sent, and the organization, since NICE otherwise keeps the one in the refresh token.
// The sign-in token is asked for with the base scopes alone, so the organization of the refresh token stays.
func (c *Client) scopeOf(key Key) string {
	if key.isSignIn() {
		return strings.Join(c.cfg.BaseScopes, " ")
	}
	var s []string
	if !c.isServiceAccount() {
		s = append(s, c.cfg.BaseScopes...)
		if key.Org != "" {
			s = append(s, "nice:org:"+key.Org)
		}
	}
	s = append(s, "nice:aud:"+key.Audience)
	if key.Project != "" {
		s = append(s, "nice:prj:"+key.Project)
	}
	return strings.Join(s, " ")
}

// fetch gets a new token for key. since is when the token the caller holds was issued:
// a token another process stored after that is used instead of spending the refresh token again.
func (c *Client) fetch(ctx context.Context, key Key, since time.Time) (Token, error) {
	if c.isServiceAccount() {
		return c.grant(ctx, key, url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret},
			"scope": {c.scopeOf(key)}})
	}
	l := c.subjectLock(key.Subject)
	l.Lock()
	defer l.Unlock()
	unlock, err := c.cfg.Store.Lock(ctx, key.Subject)
	if err != nil {
		return Token{}, &TemporaryError{Err: err}
	}
	defer unlock()

	if t, ok, err := c.cfg.Store.LoadToken(ctx, key); err == nil && ok && t.IssuedAt.After(since) && c.cfg.Now().Before(t.ExpiresAt.Add(-c.safety(key))) {
		return t, nil
	}
	rt, err := c.cfg.Store.RefreshToken(ctx, key.Subject)
	if err != nil {
		return Token{}, err
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {c.cfg.ClientID}, "scope": {c.scopeOf(key)}}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	tok, next, err := c.exchange(ctx, form)
	if err != nil {
		return Token{}, err
	}
	// The refresh token rotates: the old one is spent, so the new one must be kept before anything else.
	if next != "" {
		if err := c.saveRefresh(ctx, key.Subject, next); err != nil {
			return Token{}, err
		}
	}
	if key.Org != "" {
		c.dropOrgless(ctx, key.Subject)
	}
	_ = c.cfg.Store.SaveToken(ctx, key, tok)
	return tok, nil
}

// dropOrgless forgets the tokens of subject kept without an organization: they were for the organization
// the refresh token was in, and a refresh that named one may have moved it. They are fetched again when used.
// A zero Token saved in the Store is never handed out, even by a Store that keeps it.
func (c *Client) dropOrgless(ctx context.Context, subject string) {
	c.mu.Lock()
	var keys []Key
	for k := range c.entries {
		if k.Subject == subject && k.Org == "" {
			keys = append(keys, k)
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
	for _, k := range keys {
		_ = c.cfg.Store.SaveToken(ctx, k, Token{})
	}
}

func (c *Client) saveRefresh(ctx context.Context, subject, token string) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = c.cfg.Store.SaveRefreshToken(ctx, subject, token); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("niceauth: the new refresh token could not be kept, the session is lost: %w", err)
}

func (c *Client) grant(ctx context.Context, key Key, form url.Values) (Token, error) {
	tok, _, err := c.exchange(ctx, form)
	return tok, err
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

// exchange posts form to the token endpoint and returns the token and the new refresh token, if any.
func (c *Client) exchange(ctx context.Context, form url.Values) (Token, string, error) {
	return postToken(ctx, c.nice, c.cfg.Issuer, c.cfg.Now, form)
}

// postToken posts form to the token endpoint of issuer. A refusal is a GrantError, permanent for invalid_grant,
// invalid_client and unauthorized_client; no answer, 5xx and 429 are a TemporaryError. hc must not follow redirects:
// a redirect is a GrantError that says so, and the form, which holds the secret, is not sent to where it points.
func postToken(ctx context.Context, hc *http.Client, issuer string, now func() time.Time, form url.Values) (Token, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return Token{}, "", &TemporaryError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if isRedirect(resp.StatusCode) {
		return Token{}, "", &GrantError{Status: resp.StatusCode, Code: "redirect",
			Description: "NICE answered with a redirect to " + redirectTarget(resp) + "; nothing was sent there, check Issuer"}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Token{}, "", &TemporaryError{Err: err}
	}
	var tr tokenResponse
	_ = json.Unmarshal(raw, &tr)
	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
		return Token{}, "", &TemporaryError{Err: fmt.Errorf("token endpoint answered %d %s", resp.StatusCode, tr.Error)}
	case resp.StatusCode != http.StatusOK:
		code := tr.Error
		if code == "" {
			code = strconv.Itoa(resp.StatusCode)
		}
		return Token{}, "", &GrantError{Status: resp.StatusCode, Code: code, Description: tr.Description,
			Permanent: code == "invalid_grant" || code == "invalid_client" || code == "unauthorized_client"}
	}
	if tr.AccessToken == "" {
		return Token{}, "", &TemporaryError{Err: errors.New("token endpoint answered without an access token")}
	}
	at := now()
	tok := Token{Access: tr.AccessToken, IssuedAt: at, ExpiresAt: at.Add(time.Duration(tr.ExpiresIn) * time.Second)}
	if iat, exp, ok := jwtTimes(tr.AccessToken); ok {
		tok.IssuedAt, tok.ExpiresAt = iat, exp
	}
	return tok, tr.RefreshToken, nil
}

// jwtTimes reads iat and exp from the payload of a JWT. It does not verify anything: the
// times only schedule the renewal, and the service verifies the token.
func jwtTimes(token string) (iat, exp time.Time, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	var c struct {
		IAT int64 `json:"iat"`
		EXP int64 `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil || c.IAT == 0 || c.EXP == 0 {
		return
	}
	return time.Unix(c.IAT, 0), time.Unix(c.EXP, 0), true
}
