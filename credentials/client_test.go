package credentials

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var bg = context.Background()

func key(aud string) Key { return Key{Audience: aud, Project: "prj_a"} }

func TestTheLimitsFollowTheKindOfCaller(t *testing.T) {
	for kind, want := range map[Kind]Limits{KindUser: {16, 6}, KindServiceAccount: {8, 4}, KindBFF: {2000, 200}, KindAdminConsole: {32, 4}} {
		if got := kind.limits(); got != want {
			t.Errorf("kind %d: %+v, want %+v", kind, got, want)
		}
	}
}

func TestATokenIsKeptPerSubjectServiceAndProject(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, nil)
	a, err := c.Token(bg, key("navi"))
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c.Token(bg, key("navi")); again.Access != a.Access || f.count("client_credentials") != 1 {
		t.Fatal("a token that is still good is handed out again, not fetched again")
	}
	b, _ := c.Token(bg, key("nadi"))
	if b.Access == a.Access || f.count("client_credentials") != 2 {
		t.Fatal("another service is another token")
	}
	if p, _ := c.Token(bg, Key{Audience: "navi", Project: "prj_b"}); p.Access == a.Access {
		t.Fatal("another project is another token")
	}
	if got := f.last().Get("scope"); got != "nice:aud:navi nice:prj:prj_b" {
		t.Fatalf("the scope names one service and one project: %q", got)
	}
}

func TestTheLeastRecentlyUsedTokenGoesWhenTheCacheIsFull(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, func(cfg *Config) { cfg.Limits = &Limits{MaxCached: 3, MaxProactive: 2} })
	for _, aud := range []string{"a", "b", "c"} {
		clk.add(time.Second)
		if _, err := c.Token(bg, key(aud)); err != nil {
			t.Fatal(err)
		}
	}
	clk.add(time.Second)
	_, _ = c.Token(bg, key("a")) // a is used again, so b is the oldest
	clk.add(time.Second)
	_, _ = c.Token(bg, key("d"))
	if c.Len() != 3 {
		t.Fatalf("the cache holds at most 3 tokens: %d", c.Len())
	}
	before := f.count("client_credentials")
	_, _ = c.Token(bg, key("a"))
	_, _ = c.Token(bg, key("c"))
	_, _ = c.Token(bg, key("d"))
	if f.count("client_credentials") != before {
		t.Fatal("the tokens used recently are still there")
	}
	_, _ = c.Token(bg, key("b"))
	if f.count("client_credentials") != before+1 {
		t.Fatal("the token used least recently was dropped and is fetched again")
	}
}

func TestManyCallersForOneTokenCauseOneRequest(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	f.gate = make(chan struct{})
	c := saClient(t, f, nil)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Token(bg, key("navi")); err != nil {
				t.Error(err)
			}
		}()
	}
	eventually(t, "the first request reaches NICE", time.Second, func() bool { return f.count("client_credentials") >= 1 })
	time.Sleep(50 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	if f.count("client_credentials") != 1 {
		t.Fatalf("40 callers sent %d requests, want 1", f.count("client_credentials"))
	}
}

func TestATokenInUseIsRenewedInTheBackgroundWithoutMakingAnyoneWait(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, nil)
	run(t, c)
	first, _ := c.Token(bg, key("navi"))
	clk.add(9 * time.Minute)
	if _, _ = c.Token(bg, key("navi")); f.count("client_credentials") != 1 {
		t.Fatal("not yet due after nine minutes")
	}
	f.gate = make(chan struct{}) // the renewal will hang
	clk.add(2 * time.Minute)     // eleven minutes after it was issued
	eventually(t, "the renewal starts", time.Second, func() bool { return f.count("client_credentials") == 2 })
	start := time.Now()
	during, err := c.Token(bg, key("navi"))
	if err != nil || during.Access != first.Access || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("while the renewal runs, the old token is used at once: %v %v", err, time.Since(start))
	}
	close(f.gate)
	eventually(t, "the new token replaces the old", time.Second, func() bool {
		tok, _ := c.Token(bg, key("navi"))
		return tok.Access != first.Access
	})
	if f.count("client_credentials") != 2 {
		t.Fatalf("one renewal: %d requests", f.count("client_credentials"))
	}
}

func TestOnlyTokensUsedLatelyAreRenewedAndNoMoreThanTheCap(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, func(cfg *Config) { cfg.Limits = &Limits{MaxCached: 10, MaxProactive: 2} })
	for _, aud := range []string{"idle", "u1", "u2", "u3"} {
		if _, err := c.Token(bg, key(aud)); err != nil {
			t.Fatal(err)
		}
	}
	clk.add(5 * time.Minute)
	for _, aud := range []string{"u1", "u2", "u3"} { // used lately; idle is not
		clk.add(time.Second)
		_, _ = c.Token(bg, key(aud))
	}
	clk.add(6*time.Minute + 30*time.Second) // all four are due; idle was last used over eleven minutes ago
	before := f.count("client_credentials")
	c.renewDue()
	eventually(t, "renewals start", time.Second, func() bool { return f.count("client_credentials") > before })
	time.Sleep(100 * time.Millisecond)
	if got := f.count("client_credentials") - before; got != 2 {
		t.Fatalf("three tokens are active and at most MaxProactive=2 are renewed in the background: %d", got)
	}
	for _, ln := range f.grants[before:] {
		if strings.Contains(ln.Get("scope"), "idle") {
			t.Fatal("a token that was not used lately is not renewed in the background")
		}
	}
	// Used again, the idle token is renewed (the old one, still good, is handed out meanwhile).
	asked := f.count("client_credentials")
	if _, err := c.Token(bg, key("idle")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the idle token is renewed once it is used", time.Second, func() bool { return f.count("client_credentials") == asked+1 })
}

func TestWhileNICEIsDownTheOldTokenKeepsWorkingAndRetriesBackOff(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, func(cfg *Config) { cfg.Rand = func() float64 { return 1 } }) // full delays, no jitter
	tok, _ := c.Token(bg, key("navi"))
	f.setDown(true)
	clk.add(11 * time.Minute)
	got, err := c.Token(bg, key("navi")) // due: starts a renewal that fails
	if err != nil || got.Access != tok.Access {
		t.Fatalf("the old token is used: %v", err)
	}
	var delays []time.Duration
	for i := 0; i < 6; i++ {
		eventually(t, "the renewal fails", time.Second, func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			e := c.entries[c.normalize(key("navi"))]
			return e.flight == nil && !e.retryAt.IsZero() && e.retryAt.After(clk.now())
		})
		c.mu.Lock()
		e := c.entries[c.normalize(key("navi"))]
		delays = append(delays, e.retryAt.Sub(clk.now()))
		c.mu.Unlock()
		before := f.count("client_credentials")
		_, _ = c.Token(bg, key("navi"))
		time.Sleep(20 * time.Millisecond)
		if f.count("client_credentials") != before {
			t.Fatal("no new request inside the backoff window")
		}
		clk.add(delays[len(delays)-1])
		_, _ = c.Token(bg, key("navi")) // the window ended: one more try
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("backoff: %v, want %v", delays, want)
		}
	}
	// NICE returns: the next try works and the backoff starts over.
	f.setDown(false)
	clk.add(61 * time.Second)
	_, _ = c.Token(bg, key("navi"))
	eventually(t, "a new token arrives", 2*time.Second, func() bool {
		cur, _ := c.Token(bg, key("navi"))
		return cur.Access != tok.Access
	})
}

func TestAnExpiredTokenWithNICEDownIsAnErrorThatDoesNotHammerNICE(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, nil)
	_, _ = c.Token(bg, key("navi"))
	f.setDown(true)
	clk.add(31 * time.Minute)
	_, err := c.Token(bg, key("navi"))
	if err == nil || !IsTemporary(err) {
		t.Fatalf("expired and NICE down: %v", err)
	}
	asked := f.count("client_credentials")
	for i := 0; i < 20; i++ {
		if _, err := c.Token(bg, key("navi")); err == nil {
			t.Fatal("still down")
		}
	}
	if f.count("client_credentials") != asked {
		t.Fatalf("callers inside the backoff window do not reach NICE: %d more requests", f.count("client_credentials")-asked)
	}
}

func TestInvalidGrantEndsTheSessionOnceAndStopsTrying(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	var ended atomic.Int32
	var endedFor atomic.Value
	c := userClient(t, f, store, func(cfg *Config) {
		cfg.OnSessionEnded = func(subject string, err error) { ended.Add(1); endedFor.Store(subject) }
	})
	if _, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.live = map[string]bool{} // NICE revokes the session (logout, password changed, reuse)
	f.mu.Unlock()
	clk.add(31 * time.Minute)
	_, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"})
	var ge *GrantError
	if !errors.Is(err, ErrSessionEnded) || !errors.As(err, &ge) || ge.Code != "invalid_grant" {
		t.Fatalf("the session ended: %v", err)
	}
	asked := f.count("refresh_token")
	for i := 0; i < 5; i++ {
		if _, err := c.Token(bg, Key{Subject: "alice", Audience: "nadi", Project: "prj_a"}); !errors.Is(err, ErrSessionEnded) {
			t.Fatalf("every service of the session fails: %v", err)
		}
	}
	if f.count("refresh_token") != asked {
		t.Fatal("no retry after invalid_grant")
	}
	if ended.Load() != 1 || endedFor.Load() != "alice" {
		t.Fatalf("the application is told once: %d", ended.Load())
	}
	if _, err := store.RefreshToken(bg, "alice"); !errors.Is(err, ErrNotConnected) {
		t.Fatal("the dead refresh token is forgotten")
	}
	// After the application connected the user again, the SDK tries again.
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c.Reset("alice")
	if _, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"}); err != nil {
		t.Fatalf("after Reset: %v", err)
	}
}

func TestAWrongKeyIsReportedAndNotRetried(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	var ended atomic.Int32
	c := saClient(t, f, func(cfg *Config) {
		cfg.ClientSecret = "nice_sk_wrong.key"
		cfg.OnSessionEnded = func(string, error) { ended.Add(1) }
	})
	for i := 0; i < 4; i++ {
		_, err := c.Token(bg, key("navi"))
		if !errors.Is(err, ErrSessionEnded) {
			t.Fatalf("invalid_client: %v", err)
		}
	}
	if f.count("client_credentials") != 1 || ended.Load() != 1 {
		t.Fatalf("one request, one report: %d, %d", f.count("client_credentials"), ended.Load())
	}
}

func TestARefusedScopeIsReturnedAndDoesNotEndTheSession(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	_, err := c.Token(bg, Key{Subject: "alice", Audience: "forbidden", Project: "prj_a"})
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "invalid_scope" || errors.Is(err, ErrSessionEnded) {
		t.Fatalf("invalid_scope is the caller's mistake: %v", err)
	}
	if _, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"}); err != nil {
		t.Fatalf("the session lives on: %v", err)
	}
}

func TestRefreshTokensAreNeverUsedTwiceAtOnce(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	f.gate = make(chan struct{})
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	var wg sync.WaitGroup
	for _, aud := range []string{"navi", "nadi", "naia", "nara"} { // four services of one user at once
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Token(bg, Key{Subject: "alice", Audience: aud, Project: "prj_a"}); err != nil {
				t.Errorf("%s: %v", aud, err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	if f.maxIn.Load() != 1 {
		t.Fatalf("the refresh token rotates, so renewals of one session run one at a time; %d ran together", f.maxIn.Load())
	}
	if f.count("refresh_token") != 4 {
		t.Fatalf("four tokens, four exchanges: %d", f.count("refresh_token"))
	}
}

func TestTwoProcessesOfOneSessionSpendTheRefreshTokenOnce(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	dir := t.TempDir()
	s1, _ := NewFileStore(dir)
	s2, _ := NewFileStore(dir)
	_ = s1.SaveRefreshToken(bg, "alice", f.session())
	p1 := userClient(t, f, s1, nil)
	p2 := userClient(t, f, s2, nil)
	var wg sync.WaitGroup
	got := make([]Token, 2)
	for i, p := range []*Client{p1, p2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := p.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"})
			if err != nil {
				t.Error(err)
			}
			got[i] = tok
		}()
	}
	wg.Wait()
	if f.count("refresh_token") != 1 {
		t.Fatalf("two processes, one session: the refresh token was spent %d times", f.count("refresh_token"))
	}
	if got[0].Access == "" || got[0].Access != got[1].Access {
		t.Fatalf("the process that waited uses the result of the other: %q vs %q", got[0].Access, got[1].Access)
	}
}

func TestAStaleAnswerRenewsTheTokenOnceAndSendsTheRequestAgain(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, nil)
	var seen []string
	var bodies []string
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Header.Get("Authorization"))
		bodies = append(bodies, string(b))
		if len(seen) == 1 {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(svc.Close)
	req, _ := http.NewRequest(http.MethodPost, svc.URL, strings.NewReader(`{"a":1}`))
	resp, err := c.Do(bg, key("navi"), req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("after the retry: %v %v", resp, err)
	}
	if len(seen) != 2 || seen[0] == seen[1] || f.count("client_credentials") != 2 {
		t.Fatalf("the request is sent again with a new token: %v, %d grants", seen, f.count("client_credentials"))
	}
	if bodies[0] != `{"a":1}` || bodies[1] != `{"a":1}` {
		t.Fatalf("the body is sent again: %v", bodies)
	}
}

func TestAStaleAnswerIsRetriedOnlyOnce(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, nil)
	calls := 0
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(svc.Close)
	req, _ := http.NewRequest(http.MethodGet, svc.URL, nil)
	resp, err := c.Do(bg, key("navi"), req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || calls != 2 {
		t.Fatalf("one retry, then the answer is returned: %d calls, %v %v", calls, resp, err)
	}
	// Any other 401 is returned at once.
	calls = 0
	svc2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="wrong_audience"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(svc2.Close)
	req, _ = http.NewRequest(http.MethodGet, svc2.URL, nil)
	if resp, _ := c.Do(bg, key("navi"), req); resp.StatusCode != 401 || calls != 1 {
		t.Fatalf("only a stale or expired token is renewed: %d calls", calls)
	}
}

func TestDisconnectRevokesTheRefreshTokenAndForgetsTheSession(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	rt := f.session()
	_ = store.SaveRefreshToken(bg, "alice", rt)
	c := userClient(t, f, store, nil)
	_, _ = c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"})
	rt2, _ := store.RefreshToken(bg, "alice") // rotated by the exchange
	if err := c.Disconnect(bg, "alice"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	revoked, still := f.revoked, f.live[rt2]
	f.mu.Unlock()
	if !revoked || still {
		t.Fatalf("NICE revoked the refresh token: revoked=%v live=%v", revoked, still)
	}
	if _, err := store.RefreshToken(bg, "alice"); !errors.Is(err, ErrNotConnected) {
		t.Fatal("the token is deleted from the store")
	}
	if _, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("after disconnecting nothing is handed out: %v", err)
	}
}
