package credentials

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingStore counts the refresh tokens saved, to show a refusal leaves the session alone.
type countingStore struct {
	*MemoryStore
	savedRefresh atomic.Int32
}

func (s *countingStore) SaveRefreshToken(ctx context.Context, subject, token string) error {
	s.savedRefresh.Add(1)
	return s.MemoryStore.SaveRefreshToken(ctx, subject, token)
}

func aliceIn(org, aud string) Key {
	return Key{Subject: "alice", Org: org, Audience: aud, Project: "prj_a"}
}

func TestAuthorizeURLAsksForTheBaseScopesTheApplicationSet(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := userClient(t, f, NewMemoryStore(), func(cfg *Config) { cfg.BaseScopes = []string{"openid", "profile", "email", "offline_access"} })
	u, _ := url.Parse(startConnect(t, c, "sess-1"))
	if got := u.Query().Get("scope"); got != "openid profile email offline_access nice:org:org_1 nice:aud:navi nice:prj:prj_a" {
		t.Fatalf("the authorize URL asks for the base scopes of the application: %q", got)
	}
	if _, err := c.HandleCallback(bg, "sess-1", f.authorize(t, u.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(bg, Key{Subject: "alice-local", Audience: "nadi", Project: "prj_a"}); err != nil {
		t.Fatal(err)
	}
	if got := f.last().Get("scope"); got != "openid profile email offline_access nice:aud:nadi nice:prj:prj_a" {
		t.Fatalf("every refresh asks for the same base scopes: %q", got)
	}
}

func TestARefreshNamesTheBaseScopesAndTheOrganizationOfTheKey(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)

	tok, err := c.Token(bg, aliceIn("", "navi"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.last().Get("scope"); got != "openid offline_access nice:aud:navi nice:prj:prj_a" {
		t.Fatalf("without Org the refresh names no organization: %q", got)
	}
	if orgClaim(tok.Access) != homeOrg {
		t.Fatalf("without Org the grant stays where it is: %q", orgClaim(tok.Access))
	}

	tok, err = c.Token(bg, aliceIn("org_b", "navi"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.last().Get("scope"); got != "openid offline_access nice:org:org_b nice:aud:navi nice:prj:prj_a" {
		t.Fatalf("the refresh names the organization of the key: %q", got)
	}
	if orgClaim(tok.Access) != "org_b" {
		t.Fatalf("the token is for the organization asked: %q", orgClaim(tok.Access))
	}

	sa := saClient(t, f, nil)
	if _, err := sa.Token(bg, Key{Org: "org_b", Audience: "navi", Project: "prj_a"}); err != nil {
		t.Fatal(err)
	}
	if got := f.last().Get("scope"); got != "nice:aud:navi nice:prj:prj_a" {
		t.Fatalf("a Service Account sends neither base scopes nor an organization: %q", got)
	}
}

func TestATokenIsKeptPerOrganization(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	a, err := c.Token(bg, aliceIn("org_a", "navi"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Token(bg, aliceIn("org_b", "navi"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Access == b.Access || orgClaim(a.Access) != "org_a" || orgClaim(b.Access) != "org_b" {
		t.Fatal("two organizations are two tokens")
	}
	refreshes := f.count("refresh_token")
	if again, _ := c.Token(bg, aliceIn("org_a", "navi")); again.Access != a.Access || f.count("refresh_token") != refreshes {
		t.Fatal("the token of organization A is still kept and good after the move to B")
	}
	if c.Len() != 2 {
		t.Fatalf("two keys: %d", c.Len())
	}
}

func TestMovingToAnOrganizationDropsTheTokensKeptWithoutOne(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	_ = store.SaveRefreshToken(bg, "bob", f.session())
	c := userClient(t, f, store, nil)
	for _, k := range []Key{aliceIn("org_a", "navi"), aliceIn("", "navi"), aliceIn("", "nadi"), {Subject: "bob", Audience: "navi", Project: "prj_a"}} {
		if _, err := c.Token(bg, k); err != nil {
			t.Fatal(err)
		}
	}
	orgA, _ := c.Token(bg, aliceIn("org_a", "navi"))
	if c.Len() != 4 {
		t.Fatalf("four keys before the move: %d", c.Len())
	}
	if _, ok, _ := store.LoadToken(bg, c.normalize(aliceIn("", "navi"))); !ok {
		t.Fatal("the token without an organization is in the store before the move")
	}

	if _, err := c.Token(bg, aliceIn("org_b", "navi")); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 3 {
		t.Fatalf("the two tokens of alice without an organization are dropped, the others kept: %d", c.Len())
	}
	for _, aud := range []string{"navi", "nadi"} {
		if tok, ok, _ := store.LoadToken(bg, c.normalize(aliceIn("", aud))); ok && tok.Access != "" {
			t.Fatalf("the stored token of %s without an organization is dropped", aud)
		}
	}
	if tok, ok, _ := store.LoadToken(bg, c.normalize(Key{Subject: "bob", Audience: "navi", Project: "prj_a"})); !ok || tok.Access == "" {
		t.Fatal("another user is not touched")
	}
	refreshes := f.count("refresh_token")
	if again, _ := c.Token(bg, aliceIn("org_a", "navi")); again.Access != orgA.Access || f.count("refresh_token") != refreshes {
		t.Fatal("a token kept with an organization is not touched")
	}
	tok, err := c.Token(bg, aliceIn("", "navi"))
	if err != nil {
		t.Fatal(err)
	}
	if f.count("refresh_token") != refreshes+1 || orgClaim(tok.Access) != "org_b" {
		t.Fatalf("a key without an organization is fetched again, in the organization the grant is in now: %q", orgClaim(tok.Access))
	}
}

func TestARefusedOrganizationLeavesTheSessionAsItWas(t *testing.T) {
	for _, tc := range []struct{ org, code string }{{deniedOrg, "access_denied"}, {unusableOrg, "invalid_scope"}} {
		t.Run(tc.code, func(t *testing.T) {
			clk := newClock()
			f := newFakeNice(t, clk)
			store := &countingStore{MemoryStore: NewMemoryStore()}
			_ = store.MemoryStore.SaveRefreshToken(bg, "alice", f.session())
			var ended atomic.Int32
			c := userClient(t, f, store, func(cfg *Config) { cfg.OnSessionEnded = func(string, error) { ended.Add(1) } })
			home, err := c.Token(bg, aliceIn(homeOrg, "navi"))
			if err != nil {
				t.Fatal(err)
			}
			rt, _ := store.RefreshToken(bg, "alice")
			saved := store.savedRefresh.Load()

			_, err = c.Token(bg, aliceIn(tc.org, "navi"))
			var ge *GrantError
			if !errors.As(err, &ge) || ge.Code != tc.code || ge.Permanent || errors.Is(err, ErrSessionEnded) {
				t.Fatalf("the refusal is returned and does not end the session: %v", err)
			}
			if got, _ := store.RefreshToken(bg, "alice"); got != rt || store.savedRefresh.Load() != saved {
				t.Fatal("the refresh token is not replaced")
			}
			if ended.Load() != 0 || !c.Connected(bg, "alice") {
				t.Fatal("the session lives on")
			}
			if again, err := c.Token(bg, aliceIn(homeOrg, "navi")); err != nil || again.Access != home.Access {
				t.Fatalf("the token of the organization the user is in is still handed out: %v", err)
			}
			refreshes := f.count("refresh_token")
			other, err := c.Token(bg, aliceIn("org_b", "nadi"))
			if err != nil || orgClaim(other.Access) != "org_b" || f.count("refresh_token") != refreshes+1 {
				t.Fatalf("another key is served at once, without a backoff: %v", err)
			}
		})
	}
}

func TestTwoOrganizationsAtOnceForOneUser(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	f.gate = make(chan struct{})
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "alice", f.session())
	c := userClient(t, f, store, nil)
	orgs := []string{"org_a", "org_b"}
	got := make([]Token, len(orgs))
	var wg sync.WaitGroup
	for i, org := range orgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := c.Token(bg, aliceIn(org, "navi"))
			if err != nil {
				t.Errorf("%s: %v", org, err)
			}
			got[i] = tok
		}()
	}
	eventually(t, "the first refresh reaches NICE", time.Second, func() bool { return f.count("refresh_token") >= 1 })
	time.Sleep(30 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	if f.maxIn.Load() != 1 {
		t.Fatalf("the refresh token rotates, so the two refreshes run one at a time; %d ran together", f.maxIn.Load())
	}
	f.mu.Lock()
	var named []string
	for _, g := range f.grants {
		named = append(named, scopeOrg(g.Get("scope")))
	}
	f.mu.Unlock()
	if len(named) != 2 || named[0] == named[1] || named[0] == "" || named[1] == "" {
		t.Fatalf("each refresh names its own organization: %v", named)
	}
	for i, org := range orgs {
		if orgClaim(got[i].Access) != org {
			t.Fatalf("the caller that asked for %s got a token of %q", org, orgClaim(got[i].Access))
		}
	}
}

func TestTheStoresKeepATokenPerOrganization(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Store{"memory": NewMemoryStore(), "file": fs} {
		t.Run(name, func(t *testing.T) {
			a, b := aliceIn("org_a", "navi"), aliceIn("org_b", "navi")
			ta, tb := Token{Access: "tok-a", ExpiresAt: time.Unix(2, 0)}, Token{Access: "tok-b", ExpiresAt: time.Unix(3, 0)}
			_ = s.SaveToken(bg, a, ta)
			_ = s.SaveToken(bg, b, tb)
			if got, ok, _ := s.LoadToken(bg, a); !ok || got.Access != "tok-a" {
				t.Fatalf("organization A: %+v", got)
			}
			if got, ok, _ := s.LoadToken(bg, b); !ok || got.Access != "tok-b" {
				t.Fatalf("organization B: %+v", got)
			}
			if _, ok, _ := s.LoadToken(bg, aliceIn("", "navi")); ok {
				t.Fatal("a key without an organization is another key")
			}
			_ = s.SaveToken(bg, a, Token{})
			if got, ok, _ := s.LoadToken(bg, a); ok || got.Access != "" {
				t.Fatal("a zero token forgets the token of the key")
			}
			if _, ok, _ := s.LoadToken(bg, b); !ok {
				t.Fatal("and only that one")
			}
		})
	}
}

func TestTheFileStoreStillReadsTokensSavedWithoutAnOrganization(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir)
	// A file written before keys had an organization.
	if err := os.WriteFile(filepath.Join(dir, "token-alice+navi+prj_a"), []byte(`{"access":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := s.LoadToken(bg, aliceIn("", "navi")); !ok || got.Access != "old" {
		t.Fatalf("the old file is read for a key without an organization: %+v", got)
	}
	_ = s.SaveToken(bg, aliceIn("org_a", "navi"), Token{Access: "new"})
	_ = s.SaveRefreshToken(bg, "alice", "rt")
	if err := s.DeleteSubject(bg, "alice"); err != nil {
		t.Fatal(err)
	}
	left, _ := os.ReadDir(dir)
	var names []string
	for _, e := range left {
		names = append(names, e.Name())
	}
	if len(names) != 0 {
		t.Fatalf("DeleteSubject removes the files of both forms: %s", strings.Join(names, ", "))
	}
}
