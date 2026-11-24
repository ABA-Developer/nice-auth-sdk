package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1793329000, 0)} }

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeNice plays the token endpoint of NICE: refresh tokens rotate and a
// spent one ends the whole session, client_credentials checks one API key.
type fakeNice struct {
	srv *httptest.Server
	clk *clock

	mu       sync.Mutex
	grants   []url.Values // every grant, in order
	live     map[string]bool
	spent    map[string]bool
	revoked  bool
	next     int
	apiKey   string
	down     bool
	inflight atomic.Int32
	maxIn    atomic.Int32
	// gate, when set, holds every grant until it is closed.
	gate chan struct{}
	// ttl is the lifetime of the tokens it issues.
	ttl time.Duration
	// codes maps an authorization code to the PKCE challenge it was asked with.
	codes map[string]string
	// orgOf is the organization each live refresh token is in; NICE keeps it there.
	orgOf map[string]string
	// idToken, when set, is given with the tokens of an authorization code.
	idToken string
}

const (
	homeOrg     = "org_home"
	deniedOrg   = "org_denied"   // answered access_denied, like an organization the user left
	unusableOrg = "org_unusable" // answered invalid_scope, like a client that may not switch
)

func newFakeNice(t *testing.T, clk *clock) *fakeNice {
	f := &fakeNice{clk: clk, live: map[string]bool{}, spent: map[string]bool{}, codes: map[string]string{}, orgOf: map[string]string{}, apiKey: "nice_sk_a.secret", ttl: 30 * time.Minute}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNice) newRefresh(org string) string {
	f.next++
	rt := fmt.Sprintf("rt-%d", f.next)
	f.live[rt] = true
	f.orgOf[rt] = org
	return rt
}

// session registers a refresh token as if the user had connected.
func (f *fakeNice) session() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newRefresh(homeOrg)
}

func (f *fakeNice) count(grantType string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, g := range f.grants {
		if g.Get("grant_type") == grantType {
			n++
		}
	}
	return n
}

func (f *fakeNice) last() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.grants) == 0 {
		return nil
	}
	return f.grants[len(f.grants)-1]
}

func (f *fakeNice) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func (f *fakeNice) jwt() string { return f.jwtFor("", "") }

func (f *fakeNice) jwtFor(sub, org string) string {
	f.next++
	now := f.clk.now()
	b, _ := json.Marshal(map[string]any{"iat": now.Unix(), "exp": now.Add(f.ttl).Unix(), "jti": f.next, "sub": sub, "nice_org_id": org})
	return "h." + base64.RawURLEncoding.EncodeToString(b) + ".s"
}

// orgClaim reads nice_org_id from a token of the fake.
func orgClaim(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Org string `json:"nice_org_id"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Org
}

// scopeOrg is the organization a scope names, if any.
func scopeOrg(scope string) string {
	for _, s := range strings.Fields(scope) {
		if org, ok := strings.CutPrefix(s, "nice:org:"); ok {
			return org
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeNice) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/revoke" {
		_ = r.ParseForm()
		f.mu.Lock()
		delete(f.live, r.PostForm.Get("token"))
		f.revoked = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = r.ParseForm()
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		m := f.maxIn.Load()
		if n <= m || f.maxIn.CompareAndSwap(m, n) {
			break
		}
	}
	f.mu.Lock()
	f.grants = append(f.grants, r.PostForm)
	gate, down := f.gate, f.down
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if down {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		if r.PostForm.Get("client_secret") != f.apiKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "client authentication failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": f.jwt(), "token_type": "Bearer", "expires_in": int(f.ttl.Seconds())})
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		switch {
		case f.spent[rt]:
			// A spent refresh token used again ends the whole family.
			for k := range f.live {
				delete(f.live, k)
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		case !f.live[rt]:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		case strings.Contains(r.PostForm.Get("scope"), "nice:aud:forbidden"):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope", "error_description": "service forbidden is not available"})
		case scopeOrg(r.PostForm.Get("scope")) == deniedOrg:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied", "error_description": "the organization is not usable"})
		case scopeOrg(r.PostForm.Get("scope")) == unusableOrg:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope", "error_description": "this client cannot switch organizations"})
		default:
			org := f.orgOf[rt]
			if named := scopeOrg(r.PostForm.Get("scope")); named != "" {
				org = named
			}
			delete(f.live, rt)
			delete(f.orgOf, rt)
			f.spent[rt] = true
			writeJSON(w, http.StatusOK, map[string]any{"access_token": f.jwtFor("", org), "token_type": "Bearer", "refresh_token": f.newRefresh(org), "expires_in": int(f.ttl.Seconds())})
		}
	case "authorization_code":
		code := r.PostForm.Get("code")
		challenge, ok := f.codes[code]
		delete(f.codes, code)
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		answer := map[string]any{"access_token": f.jwtFor("usr_nice-account", homeOrg), "token_type": "Bearer", "refresh_token": f.newRefresh(homeOrg), "expires_in": int(f.ttl.Seconds())}
		if f.idToken != "" {
			answer["id_token"] = f.idToken
		}
		writeJSON(w, http.StatusOK, answer)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func eventually(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func saClient(t *testing.T, f *fakeNice, mod func(*Config)) *Client {
	t.Helper()
	cfg := Config{Issuer: f.srv.URL, ClientID: "sa_integration", ClientSecret: f.apiKey, Kind: KindServiceAccount, Now: f.clk.now, Rand: func() float64 { return 0 },
		HTTP: f.srv.Client(), Tick: 5 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func userClient(t *testing.T, f *fakeNice, store Store, mod func(*Config)) *Client {
	t.Helper()
	cfg := Config{Issuer: f.srv.URL, ClientID: "console", Kind: KindUser, Store: store, Now: f.clk.now, Rand: func() float64 { return 0 },
		HTTP: f.srv.Client(), Tick: 5 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func run(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.Run(ctx)
}

// authorize plays the browser and NICE: it accepts the authorize URL and returns the callback query.
func (f *fakeNice) authorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("state") == "" {
		t.Fatalf("the authorize request must be PKCE S256 with a state: %v", q)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	code := fmt.Sprintf("code-%d", f.next)
	f.codes[code] = q.Get("code_challenge")
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}
