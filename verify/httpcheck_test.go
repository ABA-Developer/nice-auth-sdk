package verify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

// rawToken stands for the token a request carried; the callers of NICE forward it as it is.
const rawToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c3JfMSJ9.c2lnbmF0dXJl"

func TestHTTPCheckerForwardsTheTokenAndFailsClosed(t *testing.T) {
	var body string
	var auth string
	status, answer := http.StatusOK, `{"allowed":true,"policy_version":"3"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/access-checks" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	ch := verify.NewHTTPChecker(srv.URL + "/")
	claims := verify.ClaimsWithToken(verify.Claims{Subject: "usr_1", OrgID: "org_1", ProjectID: "prj_1", PrincipalType: "user"}, rawToken)
	ctx := context.Background()

	if ok, err := ch.Check(ctx, claims, "navi.orders.read"); err != nil || !ok {
		t.Fatalf("allowed: %v %v", ok, err)
	}
	if auth != "Bearer "+rawToken || body != `{"permission":"navi.orders.read"}` {
		t.Fatalf("request: auth=%q body=%s", auth, body)
	}

	answer = `{"allowed":false,"reason":"no_binding"}`
	if ok, err := ch.Check(ctx, claims, "navi.orders.read"); err != nil || ok {
		t.Fatalf("a denial is an answer, not an error: %v %v", ok, err)
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"unauthorized": {http.StatusUnauthorized, `{"allowed":true}`},
		"forbidden":    {http.StatusForbidden, `{"allowed":true}`},
		"unavailable":  {http.StatusServiceUnavailable, ``},
		"not json":     {http.StatusOK, `<html>`},
	} {
		status, answer = tc.status, tc.body
		ok, err := ch.Check(ctx, claims, "navi.orders.read")
		if err == nil || ok {
			t.Errorf("%s must be an error, never an allow: %v %v", name, ok, err)
		}
		if err != nil && strings.Contains(err.Error(), rawToken) {
			t.Errorf("%s: the token must not leak into the error: %v", name, err)
		}
	}
}

func TestHTTPCheckerTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first, so Close does not wait for the stuck handler
	ch := verify.NewHTTPChecker(srv.URL).WithTimeout(200 * time.Millisecond)
	start := time.Now()
	if ok, err := ch.Check(context.Background(), verify.ClaimsWithToken(verify.Claims{Subject: "usr_x", OrgID: "org_x"}, rawToken), "navi.a.b"); err == nil || ok {
		t.Fatalf("a slow NICE must be an error: %v %v", ok, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the timeout bounds the wait: %v", time.Since(start))
	}
}

func TestHTTPCheckerSendsNoActAsForATokenActAs(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	t.Cleanup(srv.Close)
	operator := verify.ClaimsWithToken(verify.Claims{Subject: "usr_1", OrgID: "org_1", PrincipalType: "user", ActAs: "org_platform"}, rawToken)
	if _, err := verify.NewHTTPChecker(srv.URL).Check(context.Background(), operator, "navi.orders.delete"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["permission"] != "navi.orders.delete" {
		t.Fatalf("NICE reads nice_act_as from the token; the body carries the permission only: %v", got)
	}
}

func TestHTTPCheckerRefusesClaimsWithoutAToken(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	t.Cleanup(srv.Close)
	ok, err := verify.NewHTTPChecker(srv.URL).Check(context.Background(), &verify.Claims{Subject: "usr_1", OrgID: "org_1"}, "navi.orders.read")
	if err == nil || ok || hits != 0 {
		t.Fatalf("claims built by hand fail closed without asking NICE: %v %v, %d requests", ok, err, hits)
	}
}
