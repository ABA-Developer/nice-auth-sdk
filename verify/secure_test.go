package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// addressCases is the table of the address rule; the credentials package tests the same one.
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
		if err := checkURL("JWKSURL", c.raw, c.insecure); (err == nil) != c.ok {
			t.Errorf("%q (insecure %v): ok %v, got %v", c.raw, c.insecure, c.ok, err)
		}
	}
	err := checkURL("JWKSURL", "http://user:hunter2@nice.internal", false)
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "nice.internal") || !strings.Contains(err.Error(), "AllowInsecureHTTP") {
		t.Fatalf("the error names the address and the option, not a password: %v", err)
	}
}

func staticJWKS(t *testing.T) []byte {
	t.Helper()
	jwks, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(testSigner(t, "k1"))}})
	return jwks
}

func TestTheKeysAreNotFetchedOverPlainHTTP(t *testing.T) {
	if _, err := New(Config{Issuer: "http://nice.internal:8080", Service: vService}); err == nil || !strings.Contains(err.Error(), "nice.internal:8080") {
		t.Fatalf("a JWKS address that is plain http and not loopback is refused: %v", err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, JWKSURL: "http://nice.internal:8080/oauth/keys"}); err == nil {
		t.Fatal("a JWKSURL of its own is checked too")
	}
	// Nothing is fetched with a static key set, so the issuer is only a name.
	if _, err := New(Config{Issuer: "http://nice.internal:8080", Service: vService, StaticJWKS: staticJWKS(t)}); err != nil {
		t.Fatalf("a static JWKS needs no address: %v", err)
	}
	n := newNice(t, testSigner(t, "k1"))
	if _, err := New(Config{Issuer: vIssuer, Service: vService, JWKSURL: n.srv.URL, HTTP: n.srv.Client()}); err != nil {
		t.Fatalf("loopback needs no option: %v", err)
	}
}

// keyTrap records the Authorization header of every request it gets.
type keyTrap struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []string
}

func newKeyTrap(t *testing.T) *keyTrap {
	k := &keyTrap{}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.got = append(k.got, r.Header.Get("Authorization"))
		k.mu.Unlock()
		_, _ = w.Write([]byte(`{"allowed":true,"changes":[],"seq":"0","keys":[]}`))
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *keyTrap) hits() int { k.mu.Lock(); defer k.mu.Unlock(); return len(k.got) }

func redirecting(t *testing.T, status int, target string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTheFeedAndTheAccessCheckDoNotSendTheKeyOverPlainHTTP(t *testing.T) {
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.StartFeed(context.Background(), FeedConfig{BaseURL: "http://nice.internal:8080", APIKey: "reader-key"}); err == nil {
		t.Fatal("a feed over plain http that is not loopback does not start")
	}
	if v.feed != nil {
		t.Fatal("nothing was started")
	}
	insecure := NewHTTPChecker("http://nice.internal:8080", "reader-key")
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Checker: insecure}); err == nil {
		t.Fatal("a Verifier with such a checker is not built")
	}
	if ok, err := insecure.Check(context.Background(), &Claims{Subject: "usr_1"}, "navi.orders.read"); err == nil || ok {
		t.Fatalf("a check on its own fails closed: %v %v", ok, err)
	}
	// The explicit option, on the checker or on the Verifier, accepts it.
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Checker: NewHTTPChecker("http://nice.internal:8080", "k").WithInsecureHTTP()}); err != nil {
		t.Fatalf("WithInsecureHTTP: %v", err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Checker: NewHTTPChecker("http://nice.internal:8080", "k"), AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("AllowInsecureHTTP: %v", err)
	}
}

func TestTheKeysAreNotTakenFromARedirect(t *testing.T) {
	s := testSigner(t, "k1")
	n := newNice(t, s)
	c := newClock()
	v := verifierFor(t, n, c, "")
	trap := newKeyTrap(t)
	moved := redirecting(t, http.StatusFound, trap.srv.URL)
	v.keys.url = moved.URL
	if err := v.keys.refresh(context.Background()); err == nil {
		t.Fatal("a redirect is a failed refresh")
	}
	if trap.hits() != 0 {
		t.Fatal("the keys are not asked from the redirect target")
	}
	if _, err := v.Verify(context.Background(), s.sign(t, claims(nil))); err != nil {
		t.Fatalf("the last good keys are kept: %v", err)
	}
	app := &http.Client{}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, JWKSURL: n.srv.URL, HTTP: app}); err != nil || app.CheckRedirect != nil {
		t.Fatalf("the client of the service keeps its redirect policy: %v", err)
	}
}

func TestTheFeedAndTheAccessCheckDoNotFollowARedirect(t *testing.T) {
	trap := newKeyTrap(t)
	moved := redirecting(t, http.StatusTemporaryRedirect, trap.srv.URL)

	v := liveVerifier(t, testSigner(t, "k1"), nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := v.StartFeed(ctx, FeedConfig{BaseURL: moved.URL, APIKey: "reader-key", Wait: time.Second, MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // the replay and a few retries
	if trap.hits() != 0 || v.FeedSeq() != 0 {
		t.Fatalf("the feed is not read from the redirect target: %d requests", trap.hits())
	}

	ok, err := NewHTTPChecker(moved.URL, "reader-key").Check(context.Background(), &Claims{Subject: "usr_1"}, "navi.orders.read")
	if err == nil || ok || trap.hits() != 0 {
		t.Fatalf("a redirected check is an error and the key is not sent on: %v %v, %d requests", ok, err, trap.hits())
	}
}

func TestTheAPIKeyIsNotPrinted(t *testing.T) {
	const secret = "nice_sk_reader.very-secret-value"
	fc := FeedConfig{BaseURL: "https://auth.example.com", APIKey: secret}
	ch := NewHTTPChecker("https://auth.example.com", secret)
	type holder struct{ Feed FeedConfig }
	for name, v := range map[string]any{"FeedConfig": fc, "*FeedConfig": &fc, "*HTTPChecker": ch, "a struct that holds it": holder{fc}} {
		var b bytes.Buffer
		slog.New(slog.NewJSONHandler(&b, nil)).Info("value", slog.Any("v", v))
		slog.New(slog.NewTextHandler(&b, nil)).Info("value", slog.Any("v", v))
		out := fmt.Sprintf("%v|%+v|%#v|%s|", v, v, v, v) + b.String()
		if strings.Contains(out, secret) {
			t.Errorf("%s shows the API key: %s", name, out)
		}
		if !strings.Contains(out, "auth.example.com") {
			t.Errorf("%s still names the address: %s", name, out)
		}
	}
}
