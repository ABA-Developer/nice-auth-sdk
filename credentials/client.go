package credentials

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Key names one token: who it is for, the service and the project.
type Key struct {
	// Subject identifies the principal on the caller's side: the ID of a Service Account, or any stable
	// ID of the signed-in user in the application. It is the key of the refresh token in the Store. Prefer an
	// ID the application assigns (letters, digits, '_' and '-') over a value the user picks, such as an email:
	// a FileStore of v0.1.0 could name two such values alike, and since v0.2.0 a subject with other characters
	// is stored under a new name, so its user connects again once after the upgrade.
	Subject string
	// Audience is the slug of the service; empty asks for the platform token that opens the NICE API.
	Audience string
	// Project is the ID of the project (prj_...); empty for the platform audience.
	Project string
	// Org is the organization (org_...) of the token. For a Client acting for a user, a set Org is named in
	// every refresh of this key (nice:org), so the grant moves to it; empty keeps the organization the refresh
	// token is in now, which changes when another key moves it. A backend serving one user in several
	// organizations names Org on every call. For an ExchangeClient, empty keeps the organization of the
	// subject token. A Service Account ignores it.
	Org string
}

var defaultBaseScopes = []string{"openid", "offline_access"}

// Token is an access token with the times it was issued and expires. Printed or logged, it shows the times and not
// the token. Its JSON form is the whole token, because a Store keeps it that way: do not log a struct that holds a
// Token through a JSON encoder.
type Token struct {
	Access    string    `json:"access"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Config configures a Client.
type Config struct {
	// Issuer is the public address of NICE.
	Issuer string
	// ClientID is the OAuth client of the application, or, for a Service Account, its ID (sa_...).
	ClientID string
	// ClientSecret is the secret of a confidential OAuth client, or the API key of a Service Account.
	// It is left out of the JSON form, so a Config inside a logged struct does not show it.
	ClientSecret string `json:"-"`
	Kind         Kind
	// BaseScopes are asked for by AuthorizeURL and sent again with every refresh, since a refresh that names
	// scopes replaces those of the grant; default openid and offline_access. Add profile and email when the
	// application reads them from userinfo; the OAuth client must be allowed every scope listed. A Service
	// Account sends none.
	BaseScopes []string
	// Limits replaces the limits of Kind.
	Limits *Limits
	// Store keeps refresh tokens and shared tokens; default a MemoryStore.
	Store Store
	// RefreshAfter is how long after it was issued a token is renewed; default 10 minutes.
	RefreshAfter time.Duration
	// Jitter spreads the renewals over this extra time; default 60 seconds.
	Jitter time.Duration
	// MinBackoff and MaxBackoff bound the wait after a failed renewal; default 5 and 60 seconds.
	MinBackoff, MaxBackoff time.Duration
	// Safety is how close to its expiry a token is no longer handed out; default 10 seconds.
	Safety time.Duration
	// Tick is how often Run looks for renewals that are due; default one second.
	Tick time.Duration
	// HTTP talks to NICE and, in Do, to the services; default a client with a 30 second timeout. The calls to
	// NICE go through a copy of it that follows no redirect.
	HTTP *http.Client
	// AllowInsecureHTTP accepts a plain http address of NICE or of a service that is not loopback, for a
	// network where TLS ends somewhere else. Without it such an address is refused: the secret and the tokens
	// would cross the network in the clear. Loopback (localhost, 127.0.0.0/8, ::1) needs no option.
	AllowInsecureHTTP bool
	// OnSessionEnded is called once when NICE ended a session or refused a key for good.
	OnSessionEnded func(subject string, err error)
	Log            *slog.Logger
	// Now and Rand are for tests.
	Now  func() time.Time
	Rand func() float64
}

type flight struct {
	done chan struct{}
	tok  Token
	err  error
}

type entry struct {
	key       Key
	tok       Token
	hasTok    bool
	lastUse   time.Time
	refreshAt time.Time
	retryAt   time.Time
	backoff   time.Duration
	lastErr   error
	// noRenew stops background renewal after a refusal that retrying will not change.
	noRenew bool
	flight  *flight
}

// Client keeps the tokens of one application.
type Client struct {
	cfg Config
	lim Limits
	// nice is cfg.HTTP for the calls to NICE: it follows no redirect.
	nice *http.Client

	mu      sync.Mutex
	entries map[Key]*entry
	dead    map[string]error
	locks   map[string]*sync.Mutex
	pending memoryPending
}

// New builds a Client. Call Run to renew tokens in the background.
func New(cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("niceauth: Issuer and ClientID are required")
	}
	if cfg.Kind == KindServiceAccount && cfg.ClientSecret == "" {
		return nil, errors.New("niceauth: a Service Account needs its API key as ClientSecret")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if _, err := checkURL("Issuer", cfg.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if len(cfg.BaseScopes) == 0 {
		cfg.BaseScopes = defaultBaseScopes
	}
	cfg.BaseScopes = append([]string(nil), cfg.BaseScopes...)
	if cfg.RefreshAfter <= 0 {
		cfg.RefreshAfter = 10 * time.Minute
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	} else if cfg.Jitter == 0 {
		cfg.Jitter = 60 * time.Second
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = 5 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 60 * time.Second
	}
	if cfg.Safety <= 0 {
		cfg.Safety = 10 * time.Second
	}
	if cfg.Tick <= 0 {
		cfg.Tick = time.Second
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
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	lim := cfg.Kind.limits()
	if cfg.Limits != nil {
		lim = *cfg.Limits
	}
	return &Client{cfg: cfg, lim: lim, nice: noRedirect(cfg.HTTP), entries: map[Key]*entry{}, dead: map[string]error{}, locks: map[string]*sync.Mutex{}}, nil
}

// Len is how many tokens are kept.
func (c *Client) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.entries) }

func (c *Client) isServiceAccount() bool { return c.cfg.Kind == KindServiceAccount }

func (c *Client) normalize(k Key) Key {
	if c.isServiceAccount() && k.Subject == "" {
		k.Subject = c.cfg.ClientID
	}
	if k.Audience == "" {
		k.Audience = "nice"
	}
	return k
}

// Token returns an access token for key: the one kept if it is still good,
// otherwise a new one. While NICE is down, a token that has not expired keeps
// being handed out; one that has expired is an error, and the error says why.
func (c *Client) Token(ctx context.Context, key Key) (Token, error) {
	key = c.normalize(key)
	c.mu.Lock()
	if err := c.dead[key.Subject]; err != nil {
		c.mu.Unlock()
		return Token{}, err
	}
	now := c.cfg.Now()
	e := c.touchLocked(key, now)
	if e.hasTok && now.Before(e.tok.ExpiresAt.Add(-c.safety(key))) {
		tok := e.tok
		if !key.isSignIn() && !e.noRenew && e.flight == nil && !now.Before(e.refreshAt) && !now.Before(e.retryAt) {
			c.renewLocked(e)
		}
		c.mu.Unlock()
		return tok, nil
	}
	if f := e.flight; f != nil {
		c.mu.Unlock()
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
	if e.lastErr != nil && now.Before(e.retryAt) {
		err := e.lastErr
		c.mu.Unlock()
		return Token{}, err
	}
	f := &flight{done: make(chan struct{})}
	e.flight = f
	since := e.tok.IssuedAt
	c.mu.Unlock()

	tok, err := c.fetch(detach(ctx), key, since)
	c.finish(e, f, tok, err)
	return tok, err
}

func detach(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }

// touchLocked finds or creates the entry of key and marks it used. It keeps
// the cache within MaxCached by dropping the entries used least recently.
func (c *Client) touchLocked(key Key, now time.Time) *entry {
	e, ok := c.entries[key]
	if !ok {
		e = &entry{key: key}
		c.entries[key] = e
		if c.lim.MaxCached > 0 && len(c.entries) > c.lim.MaxCached {
			c.evictLocked(e)
		}
	}
	e.lastUse = now
	return e
}

func (c *Client) evictLocked(keep *entry) {
	for len(c.entries) > c.lim.MaxCached {
		var oldest *entry
		for _, e := range c.entries {
			if e == keep || e.flight != nil {
				continue
			}
			if oldest == nil || e.lastUse.Before(oldest.lastUse) {
				oldest = e
			}
		}
		if oldest == nil {
			return
		}
		delete(c.entries, oldest.key)
	}
}

// renewLocked starts a renewal in the background; the caller keeps using the old token meanwhile.
func (c *Client) renewLocked(e *entry) {
	f := &flight{done: make(chan struct{})}
	e.flight = f
	key, since := e.key, e.tok.IssuedAt
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		tok, err := c.fetch(ctx, key, since)
		c.finish(e, f, tok, err)
	}()
}

// finish records the outcome of a fetch and wakes those waiting for it.
func (c *Client) finish(e *entry, f *flight, tok Token, err error) {
	var ended error
	c.mu.Lock()
	now := c.cfg.Now()
	e.flight = nil
	switch {
	case err == nil:
		e.tok, e.hasTok = tok, true
		e.refreshAt = tok.IssuedAt.Add(c.cfg.RefreshAfter + time.Duration(c.cfg.Rand()*float64(c.cfg.Jitter)))
		e.retryAt, e.backoff, e.lastErr, e.noRenew = time.Time{}, 0, nil, false
	case IsTemporary(err):
		e.lastErr = err
		e.backoff = c.nextBackoff(e.backoff)
		e.retryAt = now.Add(time.Duration(float64(e.backoff) * (0.5 + 0.5*c.cfg.Rand())))
		c.cfg.Log.Warn("niceauth: could not renew the token; the old one is used until it expires",
			slog.String("service", e.key.Audience), slog.Duration("retry_in", e.retryAt.Sub(now)), slog.String("error", err.Error()))
	default:
		var ge *GrantError
		if errors.As(err, &ge) && ge.Permanent {
			ended = err
			c.endSessionLocked(e.key.Subject, err)
		} else {
			e.lastErr, e.noRenew, e.retryAt = err, true, time.Time{}
		}
	}
	f.tok, f.err = tok, err
	c.mu.Unlock()
	close(f.done)
	if ended != nil {
		c.cfg.Log.Warn("niceauth: the session ended", slog.String("subject", e.key.Subject), slog.String("error", ended.Error()))
		if c.cfg.OnSessionEnded != nil {
			c.cfg.OnSessionEnded(e.key.Subject, ended)
		}
	}
}

func (c *Client) nextBackoff(prev time.Duration) time.Duration {
	if prev <= 0 {
		return c.cfg.MinBackoff
	}
	return min(prev*2, c.cfg.MaxBackoff)
}

// endSessionLocked stops everything of subject: its tokens are dropped, its
// refresh token is forgotten, and Token fails with err until Reset.
func (c *Client) endSessionLocked(subject string, err error) {
	c.dead[subject] = err
	for k := range c.entries {
		if k.Subject == subject {
			delete(c.entries, k)
		}
	}
	if !c.isServiceAccount() {
		_ = c.cfg.Store.DeleteSubject(context.Background(), subject)
	}
}

// Reset lets Token try again for subject after the application fixed the cause
// (connected again, or replaced the key).
func (c *Client) Reset(subject string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.dead, subject)
}

// Forget drops the tokens kept for subject (for example when the user signs out).
func (c *Client) Forget(subject string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if k.Subject == subject {
			delete(c.entries, k)
		}
	}
}

// Invalidate drops the token kept for key if it is still tok, so the next Token fetches a new one at once.
func (c *Client) Invalidate(key Key, tok Token) {
	key = c.normalize(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok && e.hasTok && e.tok.Access == tok.Access {
		e.hasTok, e.retryAt, e.lastErr, e.backoff = false, time.Time{}, nil, 0
	}
}

// Run renews the tokens in use, in the background, until ctx is done. Only
// tokens used within one renewal interval are renewed, and at most
// MaxProactive of them (the most recently used); the others are fetched when
// they are used again.
func (c *Client) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.renewDue()
		}
	}
}

func (c *Client) renewDue() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	active := make([]*entry, 0, len(c.entries))
	for _, e := range c.entries {
		if !e.key.isSignIn() && now.Sub(e.lastUse) <= c.cfg.RefreshAfter+c.cfg.Jitter {
			active = append(active, e)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].lastUse.After(active[j].lastUse) })
	if c.lim.MaxProactive > 0 && len(active) > c.lim.MaxProactive {
		active = active[:c.lim.MaxProactive]
	}
	for _, e := range active {
		if e.hasTok && !e.noRenew && e.flight == nil && !now.Before(e.refreshAt) && !now.Before(e.retryAt) {
			c.renewLocked(e)
		}
	}
}
