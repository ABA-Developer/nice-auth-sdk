package verify

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestThePermissionResolverDoesNotSendTheTokenOverPlainHTTP(t *testing.T) {
	insecure := NewHTTPResolver("http://nice.internal:8080")
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: insecure}); err == nil || !strings.Contains(err.Error(), "nice.internal:8080") {
		t.Fatalf("a Verifier with such a resolver is not built, and the error names the address: %v", err)
	}
	if perms, match, err := insecure.Resolve(context.Background(), ClaimsWithToken(Claims{Subject: "usr_1", PermsRef: vRef}, "the-token")); err == nil || match || perms != nil {
		t.Fatalf("a resolution on its own fails closed: %v %v", match, err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: NewHTTPResolver("http://nice.internal:8080").WithInsecureHTTP()}); err != nil {
		t.Fatalf("WithInsecureHTTP: %v", err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: NewHTTPResolver("http://nice.internal:8080"), AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("AllowInsecureHTTP: %v", err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: NewHTTPResolver("http://127.0.0.1:8080")}); err != nil {
		t.Fatalf("loopback needs no option: %v", err)
	}
}

func TestThePermissionResolverDoesNotFollowARedirect(t *testing.T) {
	trap := newKeyTrap(t)
	moved := redirecting(t, http.StatusTemporaryRedirect, trap.srv.URL)
	perms, match, err := NewHTTPResolver(moved.URL).Resolve(context.Background(), ClaimsWithToken(Claims{Subject: "usr_1", PermsRef: vRef}, "the-token"))
	if err == nil || match || perms != nil || trap.hits() != 0 {
		t.Fatalf("a redirected resolution is an error and the token is not sent on: %v %v, %d requests", match, err, trap.hits())
	}
	app := &http.Client{}
	_, _, _ = NewHTTPResolver(moved.URL).WithHTTPClient(app).Resolve(context.Background(), ClaimsWithToken(Claims{PermsRef: vRef}, "the-token"))
	if app.CheckRedirect != nil {
		t.Fatal("the client of the service keeps its redirect policy")
	}
}
