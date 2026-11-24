package verify

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestThePermissionResolverDoesNotSendTheKeyOverPlainHTTP(t *testing.T) {
	insecure := NewHTTPResolver("http://nice.internal:8080", "reader-key")
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: insecure}); err == nil || !strings.Contains(err.Error(), "nice.internal:8080") {
		t.Fatalf("a Verifier with such a resolver is not built, and the error names the address: %v", err)
	}
	if perms, match, err := insecure.Resolve(context.Background(), &Claims{Subject: "usr_1", PermsRef: vRef}); err == nil || match || perms != nil {
		t.Fatalf("a resolution on its own fails closed: %v %v", match, err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: NewHTTPResolver("http://nice.internal:8080", "k").WithInsecureHTTP()}); err != nil {
		t.Fatalf("WithInsecureHTTP: %v", err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: NewHTTPResolver("http://nice.internal:8080", "k"), AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("AllowInsecureHTTP: %v", err)
	}
	if _, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t), Resolver: NewHTTPResolver("http://127.0.0.1:8080", "k")}); err != nil {
		t.Fatalf("loopback needs no option: %v", err)
	}
}

func TestThePermissionResolverDoesNotFollowARedirect(t *testing.T) {
	trap := newKeyTrap(t)
	moved := redirecting(t, http.StatusTemporaryRedirect, trap.srv.URL)
	perms, match, err := NewHTTPResolver(moved.URL, "reader-key").Resolve(context.Background(), &Claims{Subject: "usr_1", PermsRef: vRef})
	if err == nil || match || perms != nil || trap.hits() != 0 {
		t.Fatalf("a redirected resolution is an error and the key is not sent on: %v %v, %d requests", match, err, trap.hits())
	}
	app := &http.Client{}
	_, _, _ = NewHTTPResolver(moved.URL, "reader-key").WithHTTPClient(app).Resolve(context.Background(), &Claims{PermsRef: vRef})
	if app.CheckRedirect != nil {
		t.Fatal("the client of the service keeps its redirect policy")
	}
}

func TestTheAPIKeyOfTheResolverIsNotPrinted(t *testing.T) {
	const secret = "nice_sk_reader.very-secret-value"
	rs := NewHTTPResolver("https://auth.example.com", secret)
	type holder struct{ Resolver PermissionResolver }
	for name, v := range map[string]any{"*HTTPResolver": rs, "a struct that holds it": holder{rs}} {
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
