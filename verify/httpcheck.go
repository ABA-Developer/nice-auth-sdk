package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HTTPChecker is the AccessChecker that calls POST /api/v1/access-checks on the
// public address of NICE.
type HTTPChecker struct {
	url      string
	timeout  time.Duration
	client   *http.Client
	insecure bool
}

var _ AccessChecker = (*HTTPChecker)(nil)

// errNoToken is the error of a check or a resolution of Claims that did not come from Verify.
var errNoToken = errors.New("niceauth: the claims carry no token to forward to NICE; only Claims returned by Verify can be checked or resolved")

// NewHTTPChecker returns a checker for the NICE at baseURL. It holds no
// credential: a check forwards the token of the request as its Bearer
// credential, and NICE reads the principal, the organization, the project and
// nice_act_as from it. baseURL must be https; plain http is accepted for
// loopback, with WithInsecureHTTP, or with Config.AllowInsecureHTTP of the
// Verifier. An address that is not accepted makes New of the Verifier fail,
// and every Check an error, so the token is never sent to it.
func NewHTTPChecker(baseURL string) *HTTPChecker {
	return &HTTPChecker{url: strings.TrimRight(baseURL, "/") + "/api/v1/access-checks", timeout: 3 * time.Second, client: &http.Client{}}
}

// WithTimeout changes the time a check may take; the default is three seconds.
func (c *HTTPChecker) WithTimeout(d time.Duration) *HTTPChecker { c.timeout = d; return c }

// WithHTTPClient replaces the HTTP client, for a proxy or a custom transport.
// The check goes through a copy of it that follows no redirect.
func (c *HTTPChecker) WithHTTPClient(h *http.Client) *HTTPChecker { c.client = h; return c }

// WithInsecureHTTP accepts a plain http address of NICE that is not loopback;
// see Config.AllowInsecureHTTP.
func (c *HTTPChecker) WithInsecureHTTP() *HTTPChecker { c.insecure = true; return c }

// validate is the address rule for this checker. New of the Verifier calls it,
// with the option of its Config; Check calls it again, since a checker may be
// used without one or wrapped in another.
func (c *HTTPChecker) validate(allowInsecure bool) error {
	if allowInsecure {
		c.insecure = true
	}
	return checkURL("the address of the access check", c.url, c.insecure)
}

// String names the checker by its address.
func (c *HTTPChecker) String() string {
	if c == nil {
		return "verify.HTTPChecker(nil)"
	}
	return fmt.Sprintf("verify.HTTPChecker{URL:%q}", c.url)
}

// GoString is String.
func (c *HTTPChecker) GoString() string { return c.String() }

// checkRequest is the whole body of a check: NICE takes everything else from the forwarded token.
type checkRequest struct {
	Permission string `json:"permission"`
}

type checkResponse struct {
	Allowed bool `json:"allowed"`
}

// Check implements AccessChecker. claims must come from Verify, which keeps the
// token to forward; other Claims are an error. Any error, including a timeout or
// a non-200 answer (a 401 too), means the answer could not be had; the request
// is then refused with 503. The token is never part of an error.
func (c *HTTPChecker) Check(ctx context.Context, claims *Claims, permission string) (bool, error) {
	if err := c.validate(false); err != nil {
		return false, err
	}
	token := claims.rawToken()
	if token == "" {
		return false, errNoToken
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, err := json.Marshal(checkRequest{Permission: permission})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := noRedirect(c.client).Do(req)
	if err != nil {
		return false, fmt.Errorf("niceauth: access check: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("niceauth: access check answered HTTP %d", res.StatusCode)
	}
	var out checkResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, res.Body, 1<<16)).Decode(&out); err != nil {
		return false, fmt.Errorf("niceauth: access check answer is not valid: %w", err)
	}
	return out.Allowed, nil
}
