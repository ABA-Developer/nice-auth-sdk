// Example exchange demonstrates the backend of a service that calls another
// service on behalf of the user whose request it serves (RFC 8693 token
// exchange). It verifies the token of the request, exchanges it for a token of
// the other service, and never holds a refresh token.
//
//	NICE_ISSUER         the issuer of NICE
//	SERVICE_SLUG        the slug of this service; default agen
//	NICE_CLIENT_ID      the confidential service client of this backend
//	NICE_CLIENT_SECRET  its secret
//	TARGET_SLUG         the slug of the service to call; default nadi
//	TARGET_URL          the address of that service, e.g. https://nadi.example.com
//	LISTEN_ADDR         default 127.0.0.1:8083
package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/ABA-Developer/nice-auth-sdk/credentials"
	"github.com/ABA-Developer/nice-auth-sdk/examples/internal/env"
	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

func main() {
	issuer, slug := env.Must("NICE_ISSUER"), env.Or("SERVICE_SLUG", "agen")
	target, targetURL := env.Or("TARGET_SLUG", "nadi"), env.Must("TARGET_URL")

	v, err := verify.New(verify.Config{Issuer: issuer, Service: slug, JWKSFile: env.Or("JWKS_FILE", "jwks.json")})
	if err != nil {
		log.Fatal(err)
	}
	x, err := credentials.NewExchange(credentials.ExchangeConfig{
		Issuer: issuer, ClientID: env.Must("NICE_CLIENT_ID"), ClientSecret: env.Must("NICE_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /devices", v.Require(slug+".devices.read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Middleware verified this token. Verify first, always: the SDK reads the subject token without
		// verifying it, and NICE verifies it again on the exchange.
		userToken := strings.TrimSpace(r.Header.Get("Authorization")[len("Bearer "):])

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL+"/devices", nil)
		if err != nil {
			http.Error(w, "bad target", http.StatusInternalServerError)
			return
		}
		// An empty Org and Project keep those of the user's token. The exchanged token is kept for this user
		// token and reused until it is about to expire, so many calls cost one exchange.
		resp, err := x.DoAs(r.Context(), userToken, credentials.Key{Audience: target}, req)
		var grant *credentials.GrantError
		switch {
		case errors.As(err, &grant):
			// NICE refused: the user may not use the target service, or this backend may not act for them.
			http.Error(w, "not allowed to call "+target+": "+grant.Code, http.StatusForbidden)
			return
		case err != nil:
			http.Error(w, "upstream not available", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		// The target sees the user as the caller (sub) and this backend as the actor (act.sub).
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
	})))

	addr := env.Or("LISTEN_ADDR", "127.0.0.1:8083")
	log.Printf("%s listening on %s, calling %s for its users", slug, addr, target)
	log.Fatal(http.ListenAndServe(addr, v.Middleware(mux)))
}
