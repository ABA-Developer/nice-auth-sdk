package credentials

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTheSignInTokenComesFromARefreshWithTheBaseScopesOnly(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	tok, err := c.SignInToken(bg, "alice")
	if err != nil || tok.Access == "" {
		t.Fatalf("sign-in token: %+v %v", tok, err)
	}
	if got := f.last(); got.Get("grant_type") != "refresh_token" || got.Get("scope") != "openid offline_access" {
		t.Fatalf("one refresh with the base scopes, no audience and no organization: %v", got)
	}
	clk.add(20 * time.Minute)
	if again, err := c.SignInToken(bg, "alice"); err != nil || again.Access != tok.Access || f.count("refresh_token") != 1 {
		t.Fatalf("a sign-in token that still lives is kept: %v, %d refreshes", err, f.count("refresh_token"))
	}
	if saved, ok, _ := store.LoadToken(bg, Key{Subject: "alice", Audience: signInAudience}); !ok || saved.Access != tok.Access {
		t.Fatal("the Store keeps the sign-in token under its own key")
	}
	if _, ok, _ := store.LoadToken(bg, Key{Subject: "alice", Audience: "nice"}); ok {
		t.Fatal("the sign-in token is not the token of the NICE API")
	}
}

func TestTheSignInTokenIsFetchedAgainWellBeforeItsExpiry(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	first, err := c.SignInToken(bg, "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Thirty seconds of safety would still hand it out; an exchange needs more than a minute left.
	clk.add(28*time.Minute + 30*time.Second)
	next, err := c.SignInToken(bg, "alice")
	if err != nil || next.Access == first.Access || f.count("refresh_token") != 2 {
		t.Fatalf("a sign-in token with 90 seconds left is fetched again: %v, %d refreshes", err, f.count("refresh_token"))
	}
}

func TestTheSignInTokenIsNotRenewedInTheBackground(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	run(t, c)
	if _, err := c.SignInToken(bg, "alice"); err != nil {
		t.Fatal(err)
	}
	clk.add(11 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if _, err := c.SignInToken(bg, "alice"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := f.count("refresh_token"); n != 1 {
		t.Fatalf("the refresh token is spent only when a sign-in token is needed: %d refreshes", n)
	}
}

func TestTheSignInTokenAndAServiceTokenOfOneUserUseTheRefreshTokenOneAtATime(t *testing.T) {
	for i := 0; i < 10; i++ {
		clk := newClock()
		f := newFakeNice(t, clk)
		f.gate = make(chan struct{})
		store := NewMemoryStore()
		_ = store.SaveRefreshToken(bg, "alice", f.session())
		c := userClient(t, f, store, nil)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := c.SignInToken(bg, "alice"); err != nil {
				t.Errorf("sign-in token: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"}); err != nil {
				t.Errorf("service token: %v", err)
			}
		}()
		eventually(t, "the first refresh reaches NICE", time.Second, func() bool { return f.count("refresh_token") >= 1 })
		time.Sleep(20 * time.Millisecond)
		close(f.gate)
		wg.Wait()
		if f.maxIn.Load() != 1 || f.count("refresh_token") != 2 {
			t.Fatalf("two refreshes, one at a time: %d at once, %d in all", f.maxIn.Load(), f.count("refresh_token"))
		}
	}
}

func TestInvalidGrantOnTheSignInRefreshEndsTheSession(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	var ended atomic.Int32
	c := userClient(t, f, store, func(cfg *Config) { cfg.OnSessionEnded = func(string, error) { ended.Add(1) } })
	f.mu.Lock()
	f.live = map[string]bool{}
	f.mu.Unlock()
	_, err := c.SignInToken(bg, "alice")
	var ge *GrantError
	if !errors.Is(err, ErrSessionEnded) || !errors.As(err, &ge) || ge.Code != "invalid_grant" {
		t.Fatalf("the session ended: %v", err)
	}
	if _, err := c.Token(bg, Key{Subject: "alice", Audience: "navi", Project: "prj_a"}); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("every token of the session fails: %v", err)
	}
	if _, err := c.SignInToken(bg, "alice"); !errors.Is(err, ErrSessionEnded) || f.count("refresh_token") != 1 || ended.Load() != 1 {
		t.Fatalf("no retry and one report: %v, %d refreshes, %d reports", err, f.count("refresh_token"), ended.Load())
	}
	if _, err := store.RefreshToken(bg, "alice"); !errors.Is(err, ErrNotConnected) {
		t.Fatal("the dead refresh token is forgotten")
	}
}

func TestAServiceAccountHasNoSignInToken(t *testing.T) {
	f := newFakeNice(t, newClock())
	if _, err := saClient(t, f, nil).SignInToken(bg, "sa_integration"); err == nil {
		t.Fatal("a Service Account has no user to sign in")
	}
	if _, err := userClient(t, f, NewMemoryStore(), nil).SignInToken(bg, ""); err == nil {
		t.Fatal("a subject is required")
	}
	if len(f.grants) != 0 {
		t.Fatal("nothing is asked of NICE")
	}
}

func TestTheSignInTokenKeepsTheOrganizationOfTheRefreshToken(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, func(cfg *Config) { cfg.BaseScopes = []string{"openid", "profile", "offline_access"} })
	home, err := c.SignInToken(bg, "alice")
	if err != nil || orgClaim(home.Access) != homeOrg || f.last().Get("scope") != "openid profile offline_access" {
		t.Fatalf("the base scopes of the application and the organization of the refresh token: %v %q", err, f.last().Get("scope"))
	}
	if _, err := c.Token(bg, Key{Subject: "alice", Org: "org_b", Audience: "navi", Project: "prj_b"}); err != nil {
		t.Fatal(err)
	}
	// The move to org_b dropped the sign-in token of the home organization, so it is fetched again, in org_b.
	moved, err := c.SignInToken(bg, "alice")
	if err != nil || moved.Access == home.Access || orgClaim(moved.Access) != "org_b" || scopeOrg(f.last().Get("scope")) != "" {
		t.Fatalf("a sign-in token in the organization the refresh token is in now: %v %q", err, f.last().Get("scope"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for rt := range f.live {
		if f.orgOf[rt] != "org_b" {
			t.Fatalf("the refresh for the sign-in token leaves the refresh token in org_b: %s", f.orgOf[rt])
		}
	}
}
