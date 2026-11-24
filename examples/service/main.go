// Example service demonstrates a shared service that receives NICE access
// tokens: it verifies each token itself, guards every operation with a
// permission, checks a sensitive operation online, and reads the access change
// feed so that a token issued before an access change is refused.
//
// The service holds no credential of NICE: the feed needs none, and the online
// check and the permission resolution forward the token of the request.
//
//	NICE_ISSUER   the issuer of NICE, exactly as the iss claim of its tokens
//	SERVICE_SLUG  the slug of this service in the NICE catalog; default nadi
//	JWKS_FILE     where a copy of the keys of NICE is kept; default jwks.json
//	LISTEN_ADDR   default 127.0.0.1:8081
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/ABA-Developer/nice-auth-sdk/examples/internal/env"
	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	issuer, slug := env.Must("NICE_ISSUER"), env.Or("SERVICE_SLUG", "nadi")
	v, err := verify.New(verify.Config{
		Issuer:  issuer,
		Service: slug, // a token must be for this service alone
		// A copy of the keys on disk: a restart while NICE is down still verifies.
		JWKSFile: env.Or("JWKS_FILE", "jwks.json"),
		// The organization of the token is the tenant. See also AllowList, MapTenants and ProvisionOnFirstUse.
		Tenants: verify.OrgAsTenant(),
		// Without a Checker, an operation guarded with Sensitive() answers 503.
		Checker: verify.NewHTTPChecker(issuer),
		// Without a Resolver, a token that carries perms_ref instead of perms answers 503: NICE issues one to a
		// caller that holds more permissions than fit in a token.
		Resolver: verify.NewHTTPResolver(issuer),
	})
	if err != nil {
		log.Fatal(err)
	}
	go v.Run(ctx) // refresh the keys of NICE
	// The feed makes a token issued before an access change answer 401 token_stale within seconds. Without it, a
	// change takes effect when the token expires (30 minutes at most).
	if err := v.StartFeed(ctx, verify.FeedConfig{}); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	// Require checks the permission in the token. The names must be the ones the OpenAPI document of the
	// service declares to NICE.
	mux.Handle("GET /devices", v.Require(slug+".devices.read")(http.HandlerFunc(listDevices)))
	mux.Handle("DELETE /devices/{id}", v.Require(slug+".devices.delete", verify.Sensitive())(http.HandlerFunc(deleteDevice)))

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	// Middleware verifies the bearer token and answers 401, 403 or 503 itself; a handler behind it always has claims.
	root.Handle("/", v.Middleware(mux))

	srv := &http.Server{Addr: env.Or("LISTEN_ADDR", "127.0.0.1:8081"), Handler: root}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("%s listening on %s", slug, srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func listDevices(w http.ResponseWriter, r *http.Request) {
	claims, _ := verify.FromContext(r.Context())
	// The tenant comes from the verified token, never from a header, a query or the body of the request.
	tenant, _ := verify.TenantFromContext(r.Context())
	writeJSON(w, map[string]any{
		"tenant":          tenant,
		"project":         claims.ProjectID,
		"caller":          claims.Subject,
		"service_account": claims.IsServiceAccount(),
		// Actor is set when a backend called on behalf of the caller (token exchange); write it to the audit log.
		"acted_by": claims.Actor,
		"devices":  []string{},
	})
}

func deleteDevice(w http.ResponseWriter, r *http.Request) {
	// Reached only when NICE confirmed the access just now.
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
