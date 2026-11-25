package credentials

import (
	"net/url"
	"strings"
	"testing"
)

func endSessionQuery(t *testing.T, c *Client, req EndSessionRequest) (*url.URL, url.Values) {
	t.Helper()
	raw, err := c.EndSessionURL(req)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u, u.Query()
}

func TestEndSessionURLReturnsToTheApplication(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := userClient(t, f, NewMemoryStore(), nil)
	u, q := endSessionQuery(t, c, EndSessionRequest{PostLogoutRedirectURI: "https://app.example/signed-out", State: "s1"})
	if !strings.HasPrefix(u.String(), f.srv.URL+"/oauth/end_session?") {
		t.Fatalf("end-session address: %s", u)
	}
	if q.Get("client_id") != "console" || q.Get("post_logout_redirect_uri") != "https://app.example/signed-out" || q.Get("state") != "s1" {
		t.Fatalf("query: %v", q)
	}
	if q.Has("id_token_hint") {
		t.Fatal("no hint unless given")
	}
	if !strings.Contains(u.RawQuery, "post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fsigned-out") {
		t.Fatalf("the redirect URI is encoded: %s", u.RawQuery)
	}
}

func TestEndSessionURLCarriesTheIDTokenHint(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := userClient(t, f, NewMemoryStore(), nil)
	_, q := endSessionQuery(t, c, EndSessionRequest{IDTokenHint: "id.token.value"})
	if q.Get("id_token_hint") != "id.token.value" {
		t.Fatalf("hint: %v", q)
	}
}

func TestEndSessionURLWithoutOptionalFields(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := userClient(t, f, NewMemoryStore(), nil)
	_, q := endSessionQuery(t, c, EndSessionRequest{})
	if len(q) != 1 || q.Get("client_id") != "console" {
		t.Fatalf("only client_id: %v", q)
	}
	if f.count("") != 0 || len(f.grants) != 0 {
		t.Fatal("no request is made")
	}
}

func TestEndSessionURLRefusesAServiceAccount(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	if u, err := c.EndSessionURL(EndSessionRequest{PostLogoutRedirectURI: "https://app.example/out"}); err == nil || u != "" {
		t.Fatalf("a Service Account has no NICE session: %q, %v", u, err)
	}
}
