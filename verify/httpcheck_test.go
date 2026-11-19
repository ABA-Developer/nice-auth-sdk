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

func TestHTTPCheckerAsksNICEAndFailsClosed(t *testing.T) {
	var got map[string]string
	var auth string
	status, answer := http.StatusOK, `{"allowed":true,"policy_version":"3"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/access-checks" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	ch := verify.NewHTTPChecker(srv.URL+"/", "nice_sk_k.secret")
	claims := &verify.Claims{Subject: "usr_1", OrgID: "org_1", ProjectID: "prj_1", PrincipalType: "user"}
	ctx := context.Background()

	if ok, err := ch.Check(ctx, claims, "navi.orders.read"); err != nil || !ok {
		t.Fatalf("allowed: %v %v", ok, err)
	}
	if auth != "ApiKey nice_sk_k.secret" || got["principal_type"] != "PRINCIPAL_TYPE_USER" || got["principal_id"] != "usr_1" ||
		got["organization_id"] != "org_1" || got["project_id"] != "prj_1" || got["permission"] != "navi.orders.read" {
		t.Fatalf("request: auth=%q body=%v", auth, got)
	}
	sa := &verify.Claims{Subject: "sa_1", OrgID: "org_1", PrincipalType: "service_account"}
	if _, err := ch.Check(ctx, sa, "navi.orders.read"); err != nil || got["principal_type"] != "PRINCIPAL_TYPE_SERVICE_ACCOUNT" {
		t.Fatalf("service account: %v %v", err, got)
	}

	answer = `{"allowed":false,"reason":"no_binding"}`
	if ok, err := ch.Check(ctx, claims, "navi.orders.read"); err != nil || ok {
		t.Fatalf("a denial is an answer, not an error: %v %v", ok, err)
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"forbidden":   {http.StatusForbidden, `{"allowed":true}`},
		"unavailable": {http.StatusServiceUnavailable, ``},
		"not json":    {http.StatusOK, `<html>`},
	} {
		status, answer = tc.status, tc.body
		ok, err := ch.Check(ctx, claims, "navi.orders.read")
		if err == nil || ok {
			t.Errorf("%s must be an error, never an allow: %v %v", name, ok, err)
		}
		if err != nil && strings.Contains(err.Error(), "nice_sk_") {
			t.Errorf("%s: the key must not leak into the error: %v", name, err)
		}
	}
}

func TestHTTPCheckerTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first, so Close does not wait for the stuck handler
	ch := verify.NewHTTPChecker(srv.URL, "k").WithTimeout(200 * time.Millisecond)
	start := time.Now()
	if ok, err := ch.Check(context.Background(), &verify.Claims{Subject: "usr_x", OrgID: "org_x"}, "navi.a.b"); err == nil || ok {
		t.Fatalf("a slow NICE must be an error: %v %v", ok, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the timeout bounds the wait: %v", time.Since(start))
	}
}

func TestHTTPCheckerSendsActAsForATokenActAs(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	t.Cleanup(srv.Close)
	ch := verify.NewHTTPChecker(srv.URL, "nice_sk_k.secret")
	member := &verify.Claims{Subject: "usr_1", OrgID: "org_1", PrincipalType: "user"}
	operator := &verify.Claims{Subject: "usr_1", OrgID: "org_1", PrincipalType: "user", ActAs: "org_platform"}
	for _, c := range []*verify.Claims{member, operator} {
		if _, err := ch.Check(context.Background(), c, "navi.orders.delete"); err != nil {
			t.Fatal(err)
		}
	}
	if _, sent := got[0]["act_as"]; sent {
		t.Fatalf("a member's check carries no act_as: %v", got[0])
	}
	if got[1]["act_as"] != true {
		t.Fatalf("a check of a token act-as carries act_as true: %v", got[1])
	}
}
