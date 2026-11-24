package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxResolutionBytes bounds the answer of a resolution; a list of a thousand permissions is far below it.
const maxResolutionBytes = 1 << 20

// HTTPResolver is the PermissionResolver that calls POST /api/v1/permission-resolutions on the public address
// of NICE.
type HTTPResolver struct {
	url      string
	timeout  time.Duration
	client   *http.Client
	insecure bool
}

var _ PermissionResolver = (*HTTPResolver)(nil)

// NewHTTPResolver returns a resolver for the NICE at baseURL. It holds no credential: a resolution forwards the
// token that carries the perms_ref as its Bearer credential, and NICE reads the principal, the organization, the
// project, the service, nice_act_as and perms_ref from it. baseURL must be https; plain http is accepted for
// loopback, with WithInsecureHTTP, or with Config.AllowInsecureHTTP of the Verifier. An address that is not
// accepted makes New of the Verifier fail, and every Resolve an error, so the token is never sent to it.
func NewHTTPResolver(baseURL string) *HTTPResolver {
	return &HTTPResolver{url: strings.TrimRight(baseURL, "/") + "/api/v1/permission-resolutions", timeout: 3 * time.Second, client: &http.Client{}}
}

// WithTimeout changes the time a resolution may take; the default is three seconds.
func (r *HTTPResolver) WithTimeout(d time.Duration) *HTTPResolver { r.timeout = d; return r }

// WithHTTPClient replaces the HTTP client, for a proxy or a custom transport.
// The resolution goes through a copy of it that follows no redirect.
func (r *HTTPResolver) WithHTTPClient(h *http.Client) *HTTPResolver { r.client = h; return r }

// WithInsecureHTTP accepts a plain http address of NICE that is not loopback;
// see Config.AllowInsecureHTTP.
func (r *HTTPResolver) WithInsecureHTTP() *HTTPResolver { r.insecure = true; return r }

// validate is the address rule for this resolver. New of the Verifier calls it, with the option of its Config;
// Resolve calls it again, since a resolver may be used without one or wrapped in another.
func (r *HTTPResolver) validate(allowInsecure bool) error {
	if allowInsecure {
		r.insecure = true
	}
	return checkURL("the address of the permission resolution", r.url, r.insecure)
}

// String names the resolver by its address.
func (r *HTTPResolver) String() string {
	if r == nil {
		return "verify.HTTPResolver(nil)"
	}
	return fmt.Sprintf("verify.HTTPResolver{URL:%q}", r.url)
}

// GoString is String.
func (r *HTTPResolver) GoString() string { return r.String() }

type resolveResponse struct {
	Match       bool     `json:"match"`
	Permissions []string `json:"permissions"`
}

// Resolve implements PermissionResolver. claims must come from Verify, which keeps the token to forward; other
// Claims are an error. Any error, including a timeout or a non-200 answer (a 401 too), means the answer could
// not be had; the request is then refused with 503. The token is never part of an error.
func (r *HTTPResolver) Resolve(ctx context.Context, claims *Claims) ([]string, bool, error) {
	if err := r.validate(false); err != nil {
		return nil, false, err
	}
	token := claims.rawToken()
	if token == "" {
		return nil, false, errNoToken
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	// The body is an empty object: NICE takes everything from the forwarded token.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, strings.NewReader("{}"))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := noRedirect(r.client).Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("niceauth: permission resolution: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("niceauth: permission resolution answered HTTP %d", res.StatusCode)
	}
	var out resolveResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, res.Body, maxResolutionBytes)).Decode(&out); err != nil {
		return nil, false, fmt.Errorf("niceauth: permission resolution answer is not valid: %w", err)
	}
	if !out.Match {
		return nil, false, nil
	}
	return out.Permissions, true, nil
}
