package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HTTPChecker is the AccessChecker that calls POST /api/v1/access-checks on the
// public address of NICE.
type HTTPChecker struct {
	url      string
	apiKey   string
	timeout  time.Duration
	client   *http.Client
	insecure bool
}

var _ AccessChecker = (*HTTPChecker)(nil)

// NewHTTPChecker returns a checker for the NICE at baseURL, authenticated with
// the API key of a Service Account that holds the nice.service role
// (permission nice.platform.access.check). baseURL must be https; plain http is
// accepted for loopback, with WithInsecureHTTP, or with Config.AllowInsecureHTTP
// of the Verifier. An address that is not accepted makes New of the Verifier
// fail, and every Check an error, so the key is never sent to it.
func NewHTTPChecker(baseURL, apiKey string) *HTTPChecker {
	return &HTTPChecker{url: strings.TrimRight(baseURL, "/") + "/api/v1/access-checks", apiKey: apiKey,
		timeout: 3 * time.Second, client: &http.Client{}}
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

// String names the checker without its API key.
func (c *HTTPChecker) String() string {
	if c == nil {
		return "verify.HTTPChecker(nil)"
	}
	return fmt.Sprintf("verify.HTTPChecker{URL:%q APIKey:%s}", c.url, redacted(c.apiKey))
}

// GoString is String.
func (c *HTTPChecker) GoString() string { return c.String() }

type checkRequest struct {
	PrincipalType  string `json:"principal_type"`
	PrincipalID    string `json:"principal_id"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id,omitempty"`
	Permission     string `json:"permission"`
	ActAs          bool   `json:"act_as,omitempty"`
}

type checkResponse struct {
	Allowed bool `json:"allowed"`
}

// Check implements AccessChecker. Any error, including a timeout or a non-200
// answer, means the answer could not be had; the request is then refused with
// 503. The key is never part of an error.
func (c *HTTPChecker) Check(ctx context.Context, claims *Claims, permission string) (bool, error) {
	if err := c.validate(false); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	typ := "PRINCIPAL_TYPE_USER"
	if claims.IsServiceAccount() {
		typ = "PRINCIPAL_TYPE_SERVICE_ACCOUNT"
	}
	body, err := json.Marshal(checkRequest{PrincipalType: typ, PrincipalID: claims.Subject, OrganizationID: claims.OrgID,
		ProjectID: claims.ProjectID, Permission: permission, ActAs: claims.IsActAs()})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "ApiKey "+c.apiKey)
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
