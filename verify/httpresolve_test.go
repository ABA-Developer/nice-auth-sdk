package verify_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

func TestHTTPResolverAsksNICEForThePermissionsOfAReference(t *testing.T) {
	var got map[string]any
	var auth string
	status, answer := http.StatusOK, `{"match":true,"permissions":["navi.orders.read","navi.routes.read"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/permission-resolutions" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		got = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	rs := verify.NewHTTPResolver(srv.URL+"/", "nice_sk_k.secret")
	claims := &verify.Claims{Subject: "usr_1", OrgID: "org_1", ProjectID: "prj_1", PrincipalType: "user", Audience: []string{"navi"}, PermsRef: "v1.abc"}
	ctx := context.Background()

	perms, match, err := rs.Resolve(ctx, claims)
	if err != nil || !match || len(perms) != 2 || perms[0] != "navi.orders.read" || perms[1] != "navi.routes.read" {
		t.Fatalf("match: %v %v %v", perms, match, err)
	}
	if auth != "ApiKey nice_sk_k.secret" || got["principal_type"] != "PRINCIPAL_TYPE_USER" || got["principal_id"] != "usr_1" ||
		got["organization_id"] != "org_1" || got["project_id"] != "prj_1" || got["service"] != "navi" || got["perms_ref"] != "v1.abc" {
		t.Fatalf("request: auth=%q body=%v", auth, got)
	}
	if _, sent := got["act_as"]; sent {
		t.Fatalf("a member's resolution carries no act_as: %v", got)
	}

	sa := &verify.Claims{Subject: "sa_1", OrgID: "org_1", ProjectID: "prj_1", PrincipalType: "service_account", Audience: []string{"navi"}, PermsRef: "v1.abc"}
	if _, _, err := rs.Resolve(ctx, sa); err != nil || got["principal_type"] != "PRINCIPAL_TYPE_SERVICE_ACCOUNT" {
		t.Fatalf("service account: %v %v", err, got)
	}
	operator := &verify.Claims{Subject: "usr_1", OrgID: "org_1", ProjectID: "prj_1", PrincipalType: "user", Audience: []string{"navi"}, PermsRef: "v1.abc", ActAs: "org_platform"}
	if _, _, err := rs.Resolve(ctx, operator); err != nil || got["act_as"] != true {
		t.Fatalf("a resolution of a token act-as carries act_as true: %v %v", err, got)
	}

	for name, body := range map[string]string{"match false": `{"match":false}`, "match left out": `{}`, "a list without match": `{"permissions":["navi.orders.read"]}`} {
		answer = body
		perms, match, err := rs.Resolve(ctx, claims)
		if err != nil || match || perms != nil {
			t.Errorf("%s is an answer that the reference does not match, without permissions: %v %v %v", name, perms, match, err)
		}
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"forbidden":   {http.StatusForbidden, `{"match":true,"permissions":["navi.orders.read"]}`},
		"unavailable": {http.StatusServiceUnavailable, ``},
		"throttled":   {http.StatusTooManyRequests, `{"match":true}`},
		"not json":    {http.StatusOK, `<html>`},
	} {
		status, answer = tc.status, tc.body
		perms, match, err := rs.Resolve(ctx, claims)
		if err == nil || match || perms != nil {
			t.Errorf("%s must be an error, never a match: %v %v %v", name, perms, match, err)
		}
		if err != nil && strings.Contains(err.Error(), "nice_sk_") {
			t.Errorf("%s: the key must not leak into the error: %v", name, err)
		}
	}
}

func TestHTTPResolverTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first, so Close does not wait for the stuck handler
	rs := verify.NewHTTPResolver(srv.URL, "k").WithTimeout(200 * time.Millisecond)
	start := time.Now()
	if _, match, err := rs.Resolve(context.Background(), &verify.Claims{Subject: "usr_x", OrgID: "org_x", PermsRef: "v1.abc"}); err == nil || match {
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
	if perms, match, err := verify.NewHTTPResolver(srv.URL, "k").Resolve(context.Background(), &verify.Claims{PermsRef: "v1.abc"}); err == nil || match || perms != nil {
		t.Fatalf("an answer over 1 MiB is an error: match %v, err %v", match, err)
	}
}
