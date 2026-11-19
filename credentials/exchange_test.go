package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeExchange plays the token exchange of NICE. The token it issues names the audience, organization and project
// it was asked for and expires with the subject token at the latest.
type fakeExchange struct {
	srv *httptest.Server
	clk *clock

	mu    sync.Mutex
	forms []url.Values
	// refuse, when set, is the error code of every answer.
	refuse   string
	inflight atomic.Int32
	maxIn    atomic.Int32
	// hold, when set, keeps every exchange until it is closed.
	hold chan struct{}
	next int
}

func newFakeExchange(t *testing.T, clk *clock) *fakeExchange {
	f := &fakeExchange{clk: clk}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// subject is a user token of sub in org and prj that expires in ttl.
func subject(clk *clock, sub, org, prj string, ttl time.Duration) string {
	now := clk.now()
	b, _ := json.Marshal(map[string]any{"sub": sub, "nice_org_id": org, "prj": prj, "iat": now.Unix(), "exp": now.Add(ttl).Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(b) + ".s"
}

func (f *fakeExchange) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.forms) }

func (f *fakeExchange) serve(w http.ResponseWriter, r *http.Request) {
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
	f.forms = append(f.forms, r.PostForm)
	hold, refuse := f.hold, f.refuse
	f.next++
	jti := f.next
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" || r.PostForm.Get("client_secret") != "s3cret" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if refuse != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": refuse, "error_description": "token_stale: changed"})
		return
	}
	_, exp, _ := jwtTimes(r.PostForm.Get("subject_token"))
	now := f.clk.now()
	if lim := now.Add(30 * time.Minute); lim.Before(exp) {
		exp = lim
	}
	b, _ := json.Marshal(map[string]any{"iat": now.Unix(), "exp": exp.Unix(), "jti": jti, "scope": r.PostForm.Get("scope")})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": "h." + base64.RawURLEncoding.EncodeToString(b) + ".s",
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": int64(exp.Sub(now).Seconds())})
}

func exchangeClient(t *testing.T, f *fakeExchange) *ExchangeClient {
	t.Helper()
	x, err := NewExchange(ExchangeConfig{Issuer: f.srv.URL, ClientID: "naia-backend", ClientSecret: "s3cret", Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestExchangeOnceForManyCallsOfOneUser(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	sub := subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute)
	key := Key{Org: "org_a", Project: "prj_p", Audience: "nadi"}
	for i := 0; i < 20; i++ {
		if _, err := x.Token(context.Background(), sub, key); err != nil {
			t.Fatal(err)
		}
		clk.add(30 * time.Second)
	}
	if f.count() != 1 {
		t.Fatalf("twenty calls in ten minutes send %d exchanges, want 1", f.count())
	}
	form := f.forms[0]
	if form.Get("subject_token") != sub || form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
		form.Get("client_id") != "naia-backend" || form.Get("scope") != "nice:aud:nadi nice:org:org_a nice:prj:prj_p" {
		t.Fatalf("form %v", form)
	}
}

func TestARenewedSubjectTokenExchangesAgain(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	key := Key{Org: "org_a", Project: "prj_p", Audience: "nadi"}
	first, err := x.Token(context.Background(), subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	clk.add(10 * time.Minute)
	next, err := x.Token(context.Background(), subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), key)
	if err != nil || f.count() != 2 || next.Access == first.Access {
		t.Fatalf("a token is kept for one subject token only: %d exchanges, %v", f.count(), err)
	}
}

// A forged subject token names the user of a kept token. The SDK cannot tell: only NICE verifies it.
func TestAForgedSubjectTokenNeverGetsTheKeptTokenOfTheUser(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	key := Key{Audience: "nadi"}
	real := subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute)
	kept, err := x.Token(context.Background(), real, key)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.TrimSuffix(real, ".s") + ".forged" // the same claims, another signature
	f.mu.Lock()
	f.refuse = "invalid_grant"
	f.mu.Unlock()
	tok, err := x.Token(context.Background(), forged, key)
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "invalid_grant" || tok.Access != "" {
		t.Fatalf("the forged token gets the refusal of NICE, not a token: %v %v", tok, err)
	}
	if f.count() != 2 || f.forms[1].Get("subject_token") != forged {
		t.Fatalf("the forged token is sent to NICE: %d exchanges", f.count())
	}
	if again, err := x.Token(context.Background(), real, key); err != nil || again.Access != kept.Access || f.count() != 2 {
		t.Fatalf("the user keeps the kept token: %v, %d exchanges", err, f.count())
	}
}

func TestExchangeKeysByUserOrganizationProjectAndAudience(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	ctx := context.Background()
	u1, u2 := subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), subject(clk, "usr_2", "org_a", "prj_p", 30*time.Minute)
	for _, c := range []struct {
		sub string
		key Key
	}{
		{u1, Key{Audience: "nadi"}},
		{u1, Key{Audience: "nadi", Org: "org_a", Project: "prj_p"}}, // the same token: the defaults are the subject's
		{u1, Key{Audience: "navi"}},
		{u1, Key{Audience: "nadi", Org: "org_b", Project: "prj_q"}},
		{u1, Key{Audience: "nadi", Project: "prj_r"}},
		{u2, Key{Audience: "nadi"}},
		{u1, Key{Audience: "nice"}},
		{u1, Key{}}, // the NICE API, like Audience nice
	} {
		if _, err := x.Token(ctx, c.sub, c.key); err != nil {
			t.Fatal(err)
		}
	}
	if f.count() != 6 || x.Len() != 6 {
		t.Fatalf("%d exchanges and %d tokens kept, want 6", f.count(), x.Len())
	}
}

func TestExchangeForDifferentKeysRunsTogether(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	f.hold = make(chan struct{})
	x := exchangeClient(t, f)
	sub := subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute)
	var wg sync.WaitGroup
	for _, aud := range []string{"nadi", "navi"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := x.Token(context.Background(), sub, Key{Audience: aud}); err != nil {
				t.Error(err)
			}
		}()
	}
	eventually(t, "both exchanges in flight", 2*time.Second, func() bool { return f.inflight.Load() == 2 })
	close(f.hold)
	wg.Wait()
}

func TestConcurrentCallsForOneKeyShareOneExchange(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	f.hold = make(chan struct{})
	x := exchangeClient(t, f)
	sub := subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute)
	var wg sync.WaitGroup
	toks := make([]Token, 10)
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], _ = x.Token(context.Background(), sub, Key{Audience: "nadi"})
		}()
	}
	eventually(t, "the exchange in flight", 2*time.Second, func() bool { return f.inflight.Load() == 1 })
	time.Sleep(20 * time.Millisecond)
	close(f.hold)
	wg.Wait()
	if f.count() != 1 {
		t.Fatalf("%d exchanges, want 1", f.count())
	}
	for _, tok := range toks {
		if tok.Access == "" || tok.Access != toks[0].Access {
			t.Fatal("every caller gets the one token")
		}
	}
}

func TestKeptTokenNeverOutlivesTheSubjectToken(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	key := Key{Audience: "nadi"}
	first, err := x.Token(context.Background(), subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	short := subject(clk, "usr_1", "org_a", "prj_p", 5*time.Minute)
	tok, err := x.Token(context.Background(), short, key)
	if err != nil || f.count() != 2 || tok.Access == first.Access {
		t.Fatalf("a newer, shorter subject token exchanges again: %d exchanges, %v", f.count(), err)
	}
	if _, exp, _ := jwtTimes(short); tok.ExpiresAt.After(exp) {
		t.Fatalf("expires %v after the subject %v", tok.ExpiresAt, exp)
	}
}

func TestKeptTokenIsExchangedAgainAMinuteBeforeItExpires(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	key := Key{Audience: "nadi"}
	if _, err := x.Token(context.Background(), subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), key); err != nil {
		t.Fatal(err)
	}
	// The subject token lives longer than the token NICE gave for it, so only the margin can ask again.
	sub := subject(clk, "usr_2", "org_a", "prj_p", time.Hour)
	if _, err := x.Token(context.Background(), sub, key); err != nil || f.count() != 2 {
		t.Fatalf("%d exchanges, %v", f.count(), err)
	}
	clk.add(28 * time.Minute)
	if _, err := x.Token(context.Background(), sub, key); err != nil || f.count() != 2 {
		t.Fatalf("before the margin the kept token is used: %d exchanges, %v", f.count(), err)
	}
	clk.add(time.Minute + time.Second)
	if _, err := x.Token(context.Background(), sub, key); err != nil || f.count() != 3 {
		t.Fatalf("%d exchanges, %v", f.count(), err)
	}
}

func TestExchangeStopsOnARefusal(t *testing.T) {
	for _, code := range []string{"invalid_grant", "invalid_client", "unauthorized_client"} {
		t.Run(code, func(t *testing.T) {
			clk := newClock()
			f := newFakeExchange(t, clk)
			f.refuse = code
			x := exchangeClient(t, f)
			_, err := x.Token(context.Background(), subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), Key{Audience: "nadi"})
			var ge *GrantError
			if !errors.As(err, &ge) || ge.Code != code || !ge.Permanent || f.count() != 1 {
				t.Fatalf("one exchange and the refusal: %d, %v", f.count(), err)
			}
		})
	}
}

func TestExchangeNeedsAReadableSubjectToken(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	for _, tok := range []string{"", "opaque", "a.b.c", subject(clk, "", "org_a", "", time.Hour)} {
		if _, err := x.Token(context.Background(), tok, Key{Audience: "nadi"}); err == nil {
			t.Fatalf("%q: refused", tok)
		}
	}
	if _, err := x.Token(context.Background(), subject(clk, "usr_1", "org_a", "", -time.Minute), Key{Audience: "nadi"}); err == nil {
		t.Fatal("an expired subject token is refused")
	}
	if f.count() != 0 {
		t.Fatalf("nothing is sent: %d", f.count())
	}
}

func TestExchangeKeepsABoundedCache(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x, _ := NewExchange(ExchangeConfig{Issuer: f.srv.URL, ClientID: "naia-backend", ClientSecret: "s3cret", Now: clk.now, MaxCached: 3})
	for i := 0; i < 5; i++ {
		if _, err := x.Token(context.Background(), subject(clk, "usr_"+string(rune('a'+i)), "org_a", "prj_p", time.Hour), Key{Audience: "nadi"}); err != nil {
			t.Fatal(err)
		}
	}
	if x.Len() != 3 {
		t.Fatalf("%d kept, want 3", x.Len())
	}
	// Many subject tokens of one user stay within the bound too.
	for i := 0; i < 5; i++ {
		if _, err := x.Token(context.Background(), subject(clk, "usr_a", "org_a", "prj_p", time.Hour+time.Duration(i)*time.Second), Key{Audience: "nadi"}); err != nil {
			t.Fatal(err)
		}
	}
	if x.Len() != 3 {
		t.Fatalf("%d kept after five subject tokens of one user, want 3", x.Len())
	}
	if d, _ := NewExchange(ExchangeConfig{Issuer: "https://nice.example", ClientID: "c", ClientSecret: "s"}); d.cfg.MaxCached != 2000 {
		t.Fatalf("default bound %d", d.cfg.MaxCached)
	}
	for _, cfg := range []ExchangeConfig{{ClientID: "c", ClientSecret: "s"}, {Issuer: "i", ClientSecret: "s"}, {Issuer: "i", ClientID: "c"}} {
		if _, err := NewExchange(cfg); err == nil {
			t.Fatalf("%+v: refused", cfg)
		}
	}
}

func TestDoAsExchangesAgainOnceOnAStaleToken(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	var calls atomic.Int32
	var seen []string
	var mu sync.Mutex
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if calls.Add(1) <= 2 {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(svc.Close)
	sub := subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute)
	req, _ := http.NewRequest(http.MethodPost, svc.URL+"/reports", strings.NewReader(`{"q":1}`))
	resp, err := x.DoAs(context.Background(), sub, Key{Audience: "nadi"}, req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || calls.Load() != 2 || f.count() != 2 {
		t.Fatalf("one more exchange and one more request: status %d, %d requests, %d exchanges", resp.StatusCode, calls.Load(), f.count())
	}
	if seen[0] == seen[1] || !strings.HasPrefix(seen[1], "Bearer h.") {
		t.Fatalf("the second request carries the new token: %v", seen)
	}
	resp, err = x.DoAs(context.Background(), sub, Key{Audience: "nadi"}, req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%v %v", resp, err)
	}
	_ = resp.Body.Close()
}

func TestDoAsReturnsTheRefusalOfTheExchange(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	f.refuse = "invalid_grant"
	x := exchangeClient(t, f)
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/never", nil)
	if _, err := x.DoAs(context.Background(), subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), Key{Audience: "nadi"}, req); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("got %v", err)
	}
}
