package verify_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

func TestHTTPResolverForwardsTheTokenForThePermissionsOfAReference(t *testing.T) {
	var body string
	var auth string
	status, answer := http.StatusOK, `{"match":true,"permissions":["navi.orders.read","navi.routes.read"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/permission-resolutions" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	rs := verify.NewHTTPResolver(srv.URL + "/")
	claims := verify.ClaimsWithToken(verify.Claims{Subject: "usr_1", OrgID: "org_1", ProjectID: "prj_1", PrincipalType: "user", Audience: []string{"navi"},
		PermsRef: "v1.abc", ActAs: "org_platform"}, rawToken)
	ctx := context.Background()

	perms, match, err := rs.Resolve(ctx, claims)
	if err != nil || !match || len(perms) != 2 || perms[0] != "navi.orders.read" || perms[1] != "navi.routes.read" {
		t.Fatalf("match: %v %v %v", perms, match, err)
	}
	if auth != "Bearer "+rawToken || body != `{}` {
		t.Fatalf("NICE reads everything from the token, act-as included; the body is an empty object: auth=%q body=%s", auth, body)
	}

	for name, b := range map[string]string{"match false": `{"match":false}`, "match left out": `{}`, "a list without match": `{"permissions":["navi.orders.read"]}`} {
		answer = b
		perms, match, err := rs.Resolve(ctx, claims)
		if err != nil || match || perms != nil {
			t.Errorf("%s is an answer that the reference does not match, without permissions: %v %v %v", name, perms, match, err)
		}
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"unauthorized": {http.StatusUnauthorized, `{"match":true,"permissions":["navi.orders.read"]}`},
		"forbidden":    {http.StatusForbidden, `{"match":true,"permissions":["navi.orders.read"]}`},
		"unavailable":  {http.StatusServiceUnavailable, ``},
		"throttled":    {http.StatusTooManyRequests, `{"match":true}`},
		"not json":     {http.StatusOK, `<html>`},
	} {
		status, answer = tc.status, tc.body
		perms, match, err := rs.Resolve(ctx, claims)
		if err == nil || match || perms != nil {
			t.Errorf("%s must be an error, never a match: %v %v %v", name, perms, match, err)
		}
		if err != nil && strings.Contains(err.Error(), rawToken) {
			t.Errorf("%s: the token must not leak into the error: %v", name, err)
		}
	}
}

func TestHTTPResolverTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first, so Close does not wait for the stuck handler
	rs := verify.NewHTTPResolver(srv.URL).WithTimeout(200 * time.Millisecond)
	start := time.Now()
	if _, match, err := rs.Resolve(context.Background(), verify.ClaimsWithToken(verify.Claims{Subject: "usr_x", OrgID: "org_x", PermsRef: "v1.abc"}, rawToken)); err == nil || match {
		t.Fatalf("a slow NICE must be an error: %v %v", match, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the timeout bounds the wait: %v", time.Since(start))
	}
}

func TestHTTPResolverRefusesAnAnswerLargerThanItsLimit(t *testing.T) {
	big := `{"match":true,"permissions":["` + strings.Repeat("a", 1<<20) + `"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(big)) }))
	t.Cleanup(srv.Close)
	if perms, match, err := verify.NewHTTPResolver(srv.URL).Resolve(context.Background(), verify.ClaimsWithToken(verify.Claims{PermsRef: "v1.abc"}, rawToken)); err == nil || match || perms != nil {
		t.Fatalf("an answer over 1 MiB is an error: match %v, err %v", match, err)
	}
}

func TestHTTPResolverRefusesClaimsWithoutAToken(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"match":true,"permissions":[]}`))
	}))
	t.Cleanup(srv.Close)
	perms, match, err := verify.NewHTTPResolver(srv.URL).Resolve(context.Background(), &verify.Claims{Subject: "usr_1", PermsRef: "v1.abc"})
	if err == nil || match || perms != nil || hits != 0 {
		t.Fatalf("claims built by hand fail closed without asking NICE: %v %v, %d requests", match, err, hits)
	}
}
