package credentials

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// addressCases is the table of the address rule; the verify package tests the same one.
var addressCases = []struct {
	raw      string
	insecure bool
	ok       bool
}{
	{"https://auth.example.com", false, true},
	{"https://auth.example.com:8443/base", false, true},
	{"http://localhost:8080", false, true},
	{"http://LOCALHOST:8080", false, true},
	{"http://127.0.0.1:8080", false, true},
	{"http://127.8.9.10", false, true},
	{"http://[::1]:8080", false, true},
	{"http://nice.internal:8080", false, false},
	{"http://nice.internal:8080", true, true},
	{"http://10.0.0.5", false, false},
	{"http://localhost.example.com", false, false},
	{"/oauth/token", false, false},
	{"auth.example.com", false, false},
	{"", false, false},
	{"ftp://auth.example.com", false, false},
	{"ftp://auth.example.com", true, false},
}

func TestTheAddressRule(t *testing.T) {
	for _, c := range addressCases {
		if _, err := checkURL("Issuer", c.raw, c.insecure); (err == nil) != c.ok {
			t.Errorf("%q (insecure %v): ok %v, got %v", c.raw, c.insecure, c.ok, err)
		}
	}
	_, err := checkURL("Issuer", "http://user:hunter2@nice.internal", false)
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "nice.internal") || !strings.Contains(err.Error(), "AllowInsecureHTTP") {
		t.Fatalf("the error names the address and the option, not a password: %v", err)
	}
}

func TestAnIssuerMustBeHTTPSUnlessLoopbackOrAllowed(t *testing.T) {
	const secret = "nice_sk_a.secret-value"
	_, err := New(Config{Issuer: "http://nice.internal:8080", ClientID: "sa_integration", ClientSecret: secret, Kind: KindServiceAccount})
	if err == nil || !strings.Contains(err.Error(), "nice.internal:8080") || strings.Contains(err.Error(), secret) {
		t.Fatalf("plain http that is not loopback is refused, naming the address: %v", err)
	}
	if _, err := NewExchange(ExchangeConfig{Issuer: "http://nice.internal:8080", ClientID: "c", ClientSecret: secret}); err == nil {
		t.Fatal("the exchange client refuses it too")
	}
	if _, err := New(Config{Issuer: "http://localhost:8080", ClientID: "console"}); err != nil {
		t.Fatalf("loopback needs no option: %v", err)
	}
	if _, err := New(Config{Issuer: "http://nice.internal:8080", ClientID: "console", AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("the explicit option accepts it: %v", err)
	}
	if _, err := NewExchange(ExchangeConfig{Issuer: "http://nice.internal:8080", ClientID: "c", ClientSecret: secret, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("the explicit option accepts it for the exchange: %v", err)
	}
	setEnv(t, "http://nice.internal:8080", "sa_integration", secret)
	if _, err := NewFromEnv(); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("NewFromEnv is strict: %v", err)
	}
}

// counting counts the requests it gets.
func counting(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { n.Add(1) }))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestTheTokenEndpointIsNotFollowedToARedirect(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		other, hits := counting(t)
		nice := redirecting(t, status, other.URL+"/oauth/token")
		app := &http.Client{}
		c, err := New(Config{Issuer: nice.URL, ClientID: "sa_integration", ClientSecret: "nice_sk_a.secret", Kind: KindServiceAccount, HTTP: app})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Token(bg, key("nadi"))
		var ge *GrantError
		if !errors.As(err, &ge) || ge.Code != "redirect" || ge.Permanent || !strings.Contains(ge.Description, "redirect") {
			t.Fatalf("%d: the redirect is reported: %v", status, err)
		}
		if hits.Load() != 0 {
			t.Fatalf("%d: the secret was sent to the redirect target", status)
		}
		if app.CheckRedirect != nil {
			t.Fatal("the client of the application keeps its redirect policy")
		}
	}
}

func TestTheExchangeIsNotFollowedToARedirect(t *testing.T) {
	clk := newClock()
	other, hits := counting(t)
	nice := redirecting(t, http.StatusTemporaryRedirect, other.URL+"/oauth/token")
	x, err := NewExchange(ExchangeConfig{Issuer: nice.URL, ClientID: "naia-backend", ClientSecret: "s3cret", Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = x.Token(bg, subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), Key{Audience: "nadi"})
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "redirect" || hits.Load() != 0 {
		t.Fatalf("the redirect is reported and not followed: %v, %d requests", err, hits.Load())
	}
}

func TestDisconnectKeepsTheSessionWhenRevocationRedirects(t *testing.T) {
	other, hits := counting(t)
	nice := redirecting(t, http.StatusTemporaryRedirect, other.URL+"/oauth/revoke")
	store := NewMemoryStore()
	_ = store.SaveRefreshToken(bg, "user-1", "rt-1")
	c, err := New(Config{Issuer: nice.URL, ClientID: "console", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(bg, "user-1"); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("a redirect is not a revocation: %v", err)
	}
	if hits.Load() != 0 || !c.Connected(bg, "user-1") {
		t.Fatalf("the refresh token is not sent on and the session is kept: %d requests", hits.Load())
	}
}

func TestDoAsRefusesAPlainHTTPServiceBeforeExchanging(t *testing.T) {
	clk := newClock()
	f := newFakeExchange(t, clk)
	x := exchangeClient(t, f)
	req, _ := http.NewRequest(http.MethodGet, "http://nadi.example.com/devices", nil)
	if _, err := x.DoAs(bg, subject(clk, "usr_1", "org_a", "prj_p", 30*time.Minute), Key{Audience: "nadi"}, req); err == nil {
		t.Fatal("plain http to a service is refused")
	}
	if f.count() != 0 {
		t.Fatalf("nothing is exchanged: %d", f.count())
	}
}
