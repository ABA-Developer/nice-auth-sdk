package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// niceCall plays one endpoint of NICE and records the Authorization header and the body of every call.
type niceCall struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	answer string
	auths  []string
	bodies []string
}

func newNiceCall(t *testing.T, answer string) *niceCall {
	n := &niceCall{status: http.StatusOK, answer: answer}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		n.auths, n.bodies = append(n.auths, r.Header.Get("Authorization")), append(n.bodies, string(b))
		status, answer := n.status, n.answer
		n.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *niceCall) set(status int, answer string) {
	n.mu.Lock()
	n.status, n.answer = status, answer
	n.mu.Unlock()
}

func (n *niceCall) last() (auth, body string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.auths) == 0 {
		return "", ""
	}
	return n.auths[len(n.auths)-1], n.bodies[len(n.bodies)-1]
}

func TestASensitiveOperationForwardsTheTokenOfTheRequest(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	nice := newNiceCall(t, `{"allowed":true,"policy_version":"12"}`)
	jwks, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(s)}})
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Now: vectorNow, Checker: NewHTTPChecker(nice.srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	h := v.Middleware(v.Require("navi.orders.read", Sensitive())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	serve := func(tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/orders", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, tok := range map[string]string{"member": s.sign(t, claims(nil)), "act-as": s.sign(t, claims(map[string]any{"nice_act_as": vPlatform}))} {
		if rec := serve(tok); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if auth, body := nice.last(); auth != "Bearer "+tok || body != `{"permission":"navi.orders.read"}` {
			t.Fatalf("%s: the check forwards the token of the request and names the permission only: auth=%q body=%s", name, auth, body)
		}
	}
	nice.set(http.StatusUnauthorized, `{"error":"invalid_token"}`)
	rec := serve(s.sign(t, claims(nil)))
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusServiceUnavailable || out["error_description"] != ReasonCheckDown {
		t.Fatalf("a check NICE refuses with 401 fails closed: %d %v", rec.Code, out)
	}
}

func TestAPermsRefIsResolvedWithTheTokenThatCarriesIt(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	jwks, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(s)}})
	nice := newNiceCall(t, `{"match":true,"permissions":["navi.orders.read","navi.routes.read"]}`)
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Now: vectorNow, Resolver: NewHTTPResolver(nice.srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	tok := s.sign(t, refClaims(nil))
	c, err := v.Verify(context.Background(), tok)
	if err != nil || !c.Has("navi.routes.read") {
		t.Fatalf("resolved: %v", err)
	}
	if auth, body := nice.last(); auth != "Bearer "+tok || body != `{}` {
		t.Fatalf("the resolution forwards the token that carries perms_ref, with an empty object: auth=%q body=%s", auth, body)
	}

	nice.set(http.StatusUnauthorized, `{"error":"invalid_token"}`)
	v, err = New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Now: vectorNow, Resolver: NewHTTPResolver(nice.srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok); refusal(err).Status != http.StatusServiceUnavailable || refusal(err).Description != ReasonPermsDown {
		t.Fatalf("a resolution NICE refuses with 401 fails closed: %v", err)
	}
}
