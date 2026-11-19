package credentials

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingService plays a shared service: it records the Authorization header and body of every request and answers
// the first stale requests with 401 token_stale.
type recordingService struct {
	srv   *httptest.Server
	mu    sync.Mutex
	auth  []string
	body  []string
	stale int
}

func newRecordingService(t *testing.T, stale int) *recordingService {
	s := &recordingService{stale: stale}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		s.body = append(s.body, string(b))
		stale := len(s.auth) <= s.stale
		s.mu.Unlock()
		if stale {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// hcFor is the client of c for the service svc.
func hcFor(t *testing.T, c *Client, svc *recordingService) *http.Client {
	t.Helper()
	hc, err := c.HTTPClient(key("nadi"), svc.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

func (s *recordingService) seen() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...), append([]string(nil), s.body...)
}

func TestTransportSendsTheTokenWithoutChangingTheRequestOfTheCaller(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	svc := newRecordingService(t, 0)
	req, _ := http.NewRequest(http.MethodGet, svc.srv.URL+"/devices", nil)
	resp, err := hcFor(t, c, svc).Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request through the client: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	tok, _ := c.Token(bg, key("nadi"))
	if auth, _ := svc.seen(); len(auth) != 1 || auth[0] != "Bearer "+tok.Access {
		t.Fatalf("the service gets the token of the key: %v", auth)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("the request of the caller is not changed")
	}
}

func TestTransportUsesOneTokenForManyRequests(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	svc := newRecordingService(t, 0)
	hc := hcFor(t, c, svc)
	for i := 0; i < 10; i++ {
		resp, err := hc.Get(svc.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if n := f.count("client_credentials"); n != 1 {
		t.Fatalf("ten requests, %d grants", n)
	}
}

func TestTransportRenewsAStaleTokenOnceAndSendsTheBodyAgain(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	svc := newRecordingService(t, 1)
	resp, err := hcFor(t, c, svc).Post(svc.srv.URL, "application/json", strings.NewReader(`{"a":1}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("after the retry: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	auth, body := svc.seen()
	if len(auth) != 2 || auth[0] == auth[1] || f.count("client_credentials") != 2 {
		t.Fatalf("the request is sent again with a new token: %v, %d grants", auth, f.count("client_credentials"))
	}
	if body[0] != `{"a":1}` || body[1] != `{"a":1}` {
		t.Fatalf("the body is sent again: %v", body)
	}
}

func TestTransportReturnsTheStaleAnswerWhenTheBodyCannotBeSentAgain(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	svc := newRecordingService(t, 1)
	req, _ := http.NewRequest(http.MethodPost, svc.srv.URL, io.NopCloser(strings.NewReader(`{"a":1}`)))
	if req.GetBody != nil {
		t.Fatal("the body must not be replayable for this test")
	}
	resp, err := hcFor(t, c, svc).Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the 401 is returned: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	if auth, _ := svc.seen(); len(auth) != 1 {
		t.Fatalf("not sent again: %d requests", len(auth))
	}
}

func TestTransportReturnsTheTokenErrorWithoutCallingTheService(t *testing.T) {
	f := newFakeNice(t, newClock())
	svc := newRecordingService(t, 0)

	refused := saClient(t, f, func(cfg *Config) { cfg.ClientSecret = "nice_sk_a.wrong" })
	_, err := hcFor(t, refused, svc).Get(svc.srv.URL)
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "invalid_client" {
		t.Fatalf("a refused key is a GrantError through the client: %v", err)
	}

	f.setDown(true)
	down := saClient(t, f, nil)
	_, err = hcFor(t, down, svc).Get(svc.srv.URL)
	if err == nil || !IsTemporary(err) {
		t.Fatalf("NICE down is temporary through the client: %v", err)
	}
	if auth, _ := svc.seen(); len(auth) != 0 {
		t.Fatalf("the service is not called without a token: %d requests", len(auth))
	}
}

func TestTransportWithoutBaseDoesNotSendThroughItself(t *testing.T) {
	f := newFakeNice(t, newClock())
	plain := &http.Client{Timeout: 5 * time.Second}
	c := saClient(t, f, func(cfg *Config) { cfg.HTTP = plain })
	svc := newRecordingService(t, 0)
	hc := hcFor(t, c, svc)
	if tr, ok := hc.Transport.(*transport); !ok || tr.base != http.DefaultTransport {
		t.Fatalf("a nil base with no transport in Config.HTTP is http.DefaultTransport: %#v", hc.Transport)
	}
	if plain.Transport != nil || hc == plain || hc.Timeout != plain.Timeout {
		t.Fatal("HTTPClient copies Config.HTTP and leaves it as it is")
	}
	resp, err := hc.Get(svc.srv.URL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the token comes from NICE and the request reaches the service: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	rt, err := c.Transport(key("nadi"), svc.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if withBase := rt.(*transport); withBase.base == http.RoundTripper(withBase) {
		t.Fatal("the transport is not its own base")
	}
	c2 := saClient(t, f, nil)
	rt2, err := c2.Transport(key("nadi"), svc.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr := rt2.(*transport); tr.base != f.srv.Client().Transport {
		t.Fatal("a nil base uses the transport of Config.HTTP")
	}
}

func TestTransportRefusesARequestToAnotherHost(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	svc, other := newRecordingService(t, 0), newRecordingService(t, 0)
	_, err := hcFor(t, c, svc).Get(other.srv.URL + "/devices")
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("another host is ErrForeignHost through the client: %v", err)
	}
	if auth, _ := other.seen(); len(auth) != 0 || f.count("client_credentials") != 0 {
		t.Fatalf("nothing is sent and no token is asked for: %d requests, %d grants", len(auth), f.count("client_credentials"))
	}
}

// redirecting answers every request with a redirect to target.
func redirecting(t *testing.T, status int, target string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTransportDoesNotFollowARedirectToAnotherHost(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	other := newRecordingService(t, 0)
	svc := redirecting(t, http.StatusFound, other.srv.URL+"/stolen")
	hc, err := c.HTTPClient(key("nadi"), svc.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hc.Get(svc.URL + "/devices")
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("a redirect to another host is ErrForeignHost: %v", err)
	}
	if auth, _ := other.seen(); len(auth) != 0 {
		t.Fatalf("the token does not reach the other host: %v", auth)
	}
}

func TestTransportFollowsARedirectInsideTheService(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	var mu sync.Mutex
	var auth []string
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusFound)
			return
		}
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	t.Cleanup(svc.Close)
	hc, err := c.HTTPClient(key("nadi"), svc.URL+"/api")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(svc.URL + "/old")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("a redirect on the same origin is followed: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	tok, _ := c.Token(bg, key("nadi"))
	mu.Lock()
	defer mu.Unlock()
	if len(auth) != 1 || auth[0] != "Bearer "+tok.Access {
		t.Fatalf("the redirected request carries the token: %v", auth)
	}
}

func TestTransportNeedsASafeServiceAddress(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	for _, addr := range []string{"", "nadi", "/devices", "http://nadi.example.com", "ftp://nadi.example.com"} {
		if _, err := c.HTTPClient(key("nadi"), addr); err == nil {
			t.Fatalf("%q: refused", addr)
		}
		if _, err := c.Transport(key("nadi"), addr, nil); err == nil {
			t.Fatalf("%q: refused by Transport", addr)
		}
	}
	for _, addr := range []string{"https://nadi.example.com", "https://nadi.example.com/api/", "http://localhost:8081", "http://127.0.0.1:8081"} {
		if _, err := c.HTTPClient(key("nadi"), addr); err != nil {
			t.Fatalf("%q: %v", addr, err)
		}
	}
	insecure := saClient(t, f, func(cfg *Config) { cfg.AllowInsecureHTTP = true })
	if _, err := insecure.HTTPClient(key("nadi"), "http://nadi.internal:8081"); err != nil {
		t.Fatalf("the explicit option accepts plain http: %v", err)
	}
}

func TestDoRefusesAPlainHTTPServiceBeforeAskingForAToken(t *testing.T) {
	f := newFakeNice(t, newClock())
	c := saClient(t, f, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://nadi.example.com/devices", nil)
	if _, err := c.Do(bg, key("nadi"), req); err == nil || !strings.Contains(err.Error(), "AllowInsecureHTTP") {
		t.Fatalf("plain http to a service is refused and the option is named: %v", err)
	}
	if n := f.count("client_credentials"); n != 0 {
		t.Fatalf("no token is asked for: %d grants", n)
	}
	svc := newRecordingService(t, 0)
	req, _ = http.NewRequest(http.MethodGet, svc.srv.URL, nil)
	resp, err := c.Do(bg, key("nadi"), req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("loopback needs no option: %v %v", resp, err)
	}
	_ = resp.Body.Close()
}
