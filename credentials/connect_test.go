package credentials

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func startConnect(t *testing.T, c *Client, session string) string {
	t.Helper()
	u, err := c.AuthorizeURL(bg, ConnectRequest{Subject: "alice-local", Session: session, RedirectURI: "https://app.example/callback",
		Org: "org_1", Audience: "navi", Project: "prj_a"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestConnectingAUserKeepsTheSessionAndTheFirstToken(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := userClient(t, f, NewMemoryStore(), nil)
	authURL := startConnect(t, c, "sess-1")
	u, _ := url.Parse(authURL)
	q := u.Query()
	if got := strings.Fields(q.Get("scope")); strings.Join(got, " ") != "openid offline_access nice:org:org_1 nice:aud:navi nice:prj:prj_a" {
		t.Fatalf("the first connection asks for a refresh token and one service and project: %v", got)
	}
	if q.Get("client_id") != "console" || q.Get("redirect_uri") != "https://app.example/callback" || !strings.HasSuffix(u.Path, "/oauth/authorize") {
		t.Fatalf("authorize request: %v", authURL)
	}
	if c.Connected(bg, "alice-local") {
		t.Fatal("not connected before the callback")
	}
	conn, err := c.HandleCallback(bg, "sess-1", f.authorize(t, authURL))
	if err != nil {
		t.Fatal(err)
	}
	if conn.Subject != "alice-local" || conn.NiceSubject != "usr_nice-account" {
		t.Fatalf("connection: %+v", conn)
	}
	if !c.Connected(bg, "alice-local") {
		t.Fatal("connected after the callback")
	}
	grants := f.count("authorization_code")
	if tok, err := c.Token(bg, Key{Subject: "alice-local", Audience: "navi", Project: "prj_a"}); err != nil || tok.Access == "" {
		t.Fatalf("the first token is there at once: %v", err)
	}
	if f.count("authorization_code") != grants || f.count("refresh_token") != 0 {
		t.Fatal("the first token came with the code; nothing else was asked")
	}
	// Another service needs no new sign-in: the refresh token is used.
	if _, err := c.Token(bg, Key{Subject: "alice-local", Audience: "nadi", Project: "prj_a"}); err != nil {
		t.Fatal(err)
	}
	if f.count("refresh_token") != 1 || f.count("authorization_code") != 1 {
		t.Fatalf("one sign-in, one refresh: %d, %d", f.count("authorization_code"), f.count("refresh_token"))
	}
}

func TestACallbackThatDoesNotBelongToTheSessionIsRefused(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	c := userClient(t, f, store, nil)

	authURL := startConnect(t, c, "sess-1")
	cb := f.authorize(t, authURL)
	// Another local session received the callback: a user must not link their NICE account to someone else's user.
	if _, err := c.HandleCallback(bg, "sess-OTHER", cb); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("another session: %v", err)
	}
	if f.count("authorization_code") != 0 {
		t.Fatal("a callback of another session never reaches the token endpoint")
	}
	if c.Connected(bg, "alice-local") {
		t.Fatal("nothing is kept")
	}
	// The state is spent even by the refused callback, so it cannot be tried again.
	if _, err := c.HandleCallback(bg, "sess-1", cb); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("a state is used once: %v", err)
	}
	if _, err := c.HandleCallback(bg, "sess-1", url.Values{"code": {"x"}, "state": {"never-issued"}}); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("unknown state: %v", err)
	}
	if _, err := c.HandleCallback(bg, "sess-1", url.Values{"code": {"x"}}); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("no state: %v", err)
	}
	// An old state has expired.
	authURL = startConnect(t, c, "sess-2")
	cb = f.authorize(t, authURL)
	clk.add(11 * time.Minute)
	if _, err := c.HandleCallback(bg, "sess-2", cb); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expired state: %v", err)
	}
	// The right session completes it.
	authURL = startConnect(t, c, "sess-3")
	if _, err := c.HandleCallback(bg, "sess-3", f.authorize(t, authURL)); err != nil {
		t.Fatal(err)
	}
}

func TestADeniedConnectionIsReportedAndLeavesNothing(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := userClient(t, f, NewMemoryStore(), nil)
	authURL := startConnect(t, c, "sess-1")
	state := f.authorize(t, authURL).Get("state")
	_, err := c.HandleCallback(bg, "sess-1", url.Values{"error": {"access_denied"}, "error_description": {"organization is not usable"}, "state": {state}})
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "access_denied" {
		t.Fatalf("NICE refused: %v", err)
	}
	if c.Connected(bg, "alice-local") {
		t.Fatal("nothing is kept")
	}
}

func TestTheCallbackMayReachAnotherProcessThanTheOneThatStartedIt(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	dir := t.TempDir()
	s1, _ := NewFileStore(dir)
	s2, _ := NewFileStore(dir)
	starter, finisher := userClient(t, f, s1, nil), userClient(t, f, s2, nil)
	authURL := startConnect(t, starter, "sess-1")
	cb := f.authorize(t, authURL)
	if _, err := finisher.HandleCallback(bg, "sess-1", cb); err != nil {
		t.Fatalf("another process finishes the connection: %v", err)
	}
	if _, err := starter.HandleCallback(bg, "sess-1", cb); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("and the state is gone for the first: %v", err)
	}
	if !starter.Connected(bg, "alice-local") {
		t.Fatal("both processes see the session through the shared store")
	}
}

func TestAServiceAccountDoesNotConnectThroughABrowser(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	c := saClient(t, f, nil)
	if _, err := c.AuthorizeURL(bg, ConnectRequest{Subject: "x", Session: "s", RedirectURI: "https://a/cb"}); err == nil {
		t.Fatal("a Service Account proves its key, it does not sign in")
	}
}

func TestDisconnectKeepsTheSessionWhenNICECannotBeReached(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	store := NewMemoryStore()
	c := userClient(t, f, store, nil)
	authURL := startConnect(t, c, "sess-1")
	if _, err := c.HandleCallback(bg, "sess-1", f.authorize(t, authURL)); err != nil {
		t.Fatal(err)
	}
	f.srv.Close()
	err := c.Disconnect(bg, "alice-local")
	if !IsTemporary(err) {
		t.Fatalf("NICE is unreachable: %v", err)
	}
	if !c.Connected(bg, "alice-local") {
		t.Fatal("the user must not look disconnected while the refresh token still works")
	}
}
