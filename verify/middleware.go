package verify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type ctxKey int

const (
	claimsKey ctxKey = iota
	tenantKey
)

// FromContext returns the verified claims Middleware stored for the request.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}

// TenantFromContext returns the tenant the TenantResolver chose for the request.
func TenantFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tenantKey).(string)
	return t, ok
}

// Middleware verifies the bearer token of every request, resolves the tenant of
// its organization, and stores both in the context. It answers 401 for a token
// that is not valid, 403 for an organization the service does not accept, and 503
// when the keys or the tenant cannot be had.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			writeError(w, v.reject(invalid("missing_token")))
			return
		}
		c, err := v.Verify(r.Context(), token)
		if err != nil {
			var e *Error
			if errors.As(err, &e) {
				writeError(w, e)
				return
			}
			writeError(w, unavailable("temporarily_unavailable", "verification_failed"))
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, c)
		if v.cfg.Tenants != nil {
			tenant, err := v.cfg.Tenants.Resolve(ctx, c.OrgID)
			switch {
			case errors.Is(err, ErrUnknownOrg):
				writeError(w, v.reject(forbidden(ReasonOrg)))
				return
			case err != nil:
				writeError(w, v.reject(unavailable("temporarily_unavailable", "tenant_unavailable")))
				return
			}
			ctx = context.WithValue(ctx, tenantKey, tenant)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireOption refines Require.
type RequireOption func(*requirement)

type requirement struct {
	project   func(*http.Request) string
	sensitive bool
}

// WithProject gives the project the request names (a header, path or query
// value); a request that names another project than the token is refused.
func WithProject(of func(*http.Request) string) RequireOption {
	return func(r *requirement) { r.project = of }
}

// Sensitive makes the operation check access online, in addition to the token.
func Sensitive() RequireOption { return func(r *requirement) { r.sensitive = true } }

// Require guards an operation: the token must hold permission, name the same
// project as the request when it names one, and, for a sensitive operation,
// pass the online check. It must run inside Middleware.
func (v *Verifier) Require(permission string, opts ...RequireOption) func(http.Handler) http.Handler {
	var req requirement
	for _, o := range opts {
		o(&req)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := FromContext(r.Context())
			if !ok {
				writeError(w, v.reject(invalid("missing_token")))
				return
			}
			if !c.Has(permission) {
				writeError(w, v.reject(forbidden(ReasonPermission)))
				return
			}
			if req.project != nil {
				if p := req.project(r); p != "" && p != c.ProjectID {
					writeError(w, v.reject(forbidden(ReasonProject)))
					return
				}
			}
			if req.sensitive {
				if v.cfg.Checker == nil {
					writeError(w, v.reject(unavailable("temporarily_unavailable", ReasonCheckDown)))
					return
				}
				allowed, err := v.cfg.Checker.Check(r.Context(), c, permission)
				switch {
				case err != nil:
					writeError(w, v.reject(unavailable("temporarily_unavailable", ReasonCheckDown)))
					return
				case !allowed:
					writeError(w, v.reject(forbidden(ReasonCheck)))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	t := strings.TrimSpace(h[7:])
	return t, t != ""
}

func writeError(w http.ResponseWriter, e *Error) {
	switch e.Status {
	case http.StatusUnauthorized:
		if e.Description == "missing_token" {
			w.Header().Set("WWW-Authenticate", "Bearer")
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+e.Description+`"`)
		}
	case http.StatusServiceUnavailable:
		w.Header().Set("Retry-After", "5")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Code, "error_description": e.Description})
}
