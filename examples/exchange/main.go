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
//
// Every route takes the token of the user for this service as its Bearer:
//
//	GET /devices           calls TARGET_URL/devices with DoAs, the address written by hand
//	GET /services          prints the service map of the user: which services in which projects
//	GET /operations        prints the operations of TARGET_SLUG the user may call; ?etag=W/"..." prints
//	                       "unchanged" while the list is the same
//	GET /schemas           prints the full schemas of ?keys=a,b of TARGET_SLUG as JSON
//	GET /call/{operation}  calls one read operation of TARGET_SLUG found through the map, with
//	                       ?org=org_...&project=prj_... and the path and query fields of the operation,
//	                       e.g. /call/listDevices?project=prj_... or /call/getDevice?project=prj_...&id=dev-1;
//	                       the properties the document marks x-secret are removed from the answer
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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
		userToken := bearer(r)

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
		relay(w, resp)
	})))

	// The service map: where the user may call which service, read from NICE and not written by hand. It costs the
	// one exchange for the NICE API and none per service or project.
	mux.HandleFunc("GET /services", func(w http.ResponseWriter, r *http.Request) {
		m, err := x.Services(r.Context(), bearer(r))
		if err != nil {
			discoveryError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, s := range m.Services {
			_, _ = fmt.Fprintf(w, "service %s (%s) at %s%s\n", s.Slug, s.Name, s.Endpoint, s.BasePath)
		}
		for _, o := range m.Organizations {
			for _, p := range o.Projects {
				_, _ = fmt.Fprintf(w, "%s %s / %s %s: %s\n", o.ID, o.Name, p.ID, p.Name, strings.Join(p.Services, ", "))
			}
			if o.ProjectsTruncated {
				_, _ = fmt.Fprintf(w, "%s %s: NICE listed only part of its projects\n", o.ID, o.Name)
			}
		}
	})

	// The operations of the target the user may call, read page by page by the SDK. With ?etag= the list is read only
	// when it changed since the answer that gave that ETag; an agent keeps the list and the ETag between questions.
	mux.HandleFunc("GET /operations", func(w http.ResponseWriter, r *http.Request) {
		ops, changed, err := x.ServiceOperationsIfChanged(r.Context(), bearer(r), target, r.URL.Query().Get("etag"))
		if err != nil {
			discoveryError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !changed {
			_, _ = fmt.Fprintln(w, "unchanged")
			return
		}
		_, _ = fmt.Fprintf(w, "%s catalog %d, %d operations, etag %s\n", ops.Service, ops.CatalogVersion, len(ops.Operations), ops.ETag)
		for _, o := range ops.Operations {
			_, _ = fmt.Fprintf(w, "%s %s %s (%s): %s\n", o.Key, o.Method, o.Path, o.Permission, o.Description)
			for _, f := range o.RequestFields {
				_, _ = fmt.Fprintf(w, "  %s %s required=%v type=%s format=%s enum=%v: %s\n", f.Location, f.Name, f.Required, f.Type,
					f.Format, f.Enum, f.Description)
			}
		}
	})

	// The full schemas of some operations of the target, ?keys=a,b; the SDK sends them 20 to a request.
	mux.HandleFunc("GET /schemas", func(w http.ResponseWriter, r *http.Request) {
		keys := strings.Split(r.URL.Query().Get("keys"), ",")
		schemas, err := x.OperationSchemas(r.Context(), bearer(r), target, keys)
		if err != nil {
			discoveryError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(schemas)
	})

	// One read operation of the target, found through the map: the address, the method and the headers come from
	// NICE, the values from the query of this request.
	mux.HandleFunc("GET /call/{operation}", func(w http.ResponseWriter, r *http.Request) {
		userToken, q := bearer(r), r.URL.Query()
		m, err := x.Services(r.Context(), userToken)
		if err != nil {
			discoveryError(w, err)
			return
		}
		var svc credentials.MapService
		for _, s := range m.Services {
			if s.Slug == target {
				svc = s
			}
		}
		// NICE answers 404 not_found when the user may not call the target anywhere.
		ops, err := x.ServiceOperations(r.Context(), userToken, target)
		if err != nil {
			discoveryError(w, err)
			return
		}
		var op credentials.ServiceOperation
		for _, o := range ops.Operations {
			if o.Key == r.PathValue("operation") {
				op = o
			}
		}
		switch {
		case svc.Slug == "" || op.Key == "":
			http.Error(w, "the user may not call this operation of "+target, http.StatusNotFound)
			return
		case op.Method != http.MethodGet:
			// A policy of this example, not of the SDK: writes and op.Sensitive are the choice of the application.
			http.Error(w, "this example calls read operations only", http.StatusBadRequest)
			return
		}
		call := credentials.OperationCall{Service: svc, Operation: op, Org: q.Get("org"), Project: q.Get("project"),
			PathParams: map[string]string{}, Query: url.Values{}}
		for _, f := range op.RequestFields {
			switch {
			case f.Location == "path":
				call.PathParams[f.Name] = q.Get(f.Name)
			case f.Location == "query" && q.Has(f.Name):
				call.Query[f.Name] = q[f.Name]
			}
		}
		resp, err := x.CallOperation(r.Context(), userToken, call)
		var grant *credentials.GrantError
		switch {
		case errors.Is(err, credentials.ErrInvalidOperationCall):
			// Nothing was exchanged or sent: a path parameter is missing or is not one plain segment.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		case errors.As(err, &grant):
			http.Error(w, "not allowed to call "+target+" in this project: "+grant.Code, http.StatusForbidden)
			return
		case err != nil:
			http.Error(w, "upstream not available", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		// Before the answer reaches the user, or a model, the properties the document marks x-secret are removed.
		schemas, err := x.OperationSchemas(r.Context(), userToken, target, []string{op.Key})
		if err != nil || len(schemas.Schemas) == 0 {
			http.Error(w, "the schema of the operation cannot be read", http.StatusBadGateway)
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			http.Error(w, "upstream not available", http.StatusBadGateway)
			return
		}
		if clean, err := credentials.RedactSecrets(schemas.Schemas[0].ResponseSchema(resp.StatusCode), body); err == nil {
			body = clean
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	addr := env.Or("LISTEN_ADDR", "127.0.0.1:8083")
	log.Printf("%s listening on %s, calling %s for its users", slug, addr, target)
	log.Fatal(http.ListenAndServe(addr, v.Middleware(mux)))
}

// bearer is the token of the request, which Middleware verified.
func bearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

func relay(w http.ResponseWriter, resp *http.Response) {
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

// discoveryError answers a failure of Services or ServiceOperations.
func discoveryError(w http.ResponseWriter, err error) {
	var grant *credentials.GrantError
	var api *credentials.APIError
	switch {
	case errors.As(err, &grant):
		http.Error(w, "NICE refused the exchange: "+grant.Code, http.StatusForbidden)
	case credentials.IsTemporary(err):
		http.Error(w, "NICE is not available", http.StatusServiceUnavailable)
	case errors.As(err, &api):
		http.Error(w, "NICE answered "+api.Code, api.Status)
	default:
		http.Error(w, "the services cannot be read", http.StatusBadGateway)
	}
}
