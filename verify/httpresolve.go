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

// maxResolutionBytes bounds the answer of a resolution; a list of a thousand permissions is far below it.
const maxResolutionBytes = 1 << 20

// HTTPResolver is the PermissionResolver that calls POST /api/v1/permission-resolutions on the public address
// of NICE.
type HTTPResolver struct {
	url      string
	apiKey   string
	timeout  time.Duration
	client   *http.Client
	insecure bool
}

var _ PermissionResolver = (*HTTPResolver)(nil)

// NewHTTPResolver returns a resolver for the NICE at baseURL, authenticated with the API key of a Service
// Account that holds the nice.service role (permission nice.platform.access.check): the key of the access
// check and of the feed. baseURL must be https; plain http is accepted for loopback, with WithInsecureHTTP, or
// with Config.AllowInsecureHTTP of the Verifier. An address that is not accepted makes New of the Verifier
// fail, and every Resolve an error, so the key is never sent to it.
func NewHTTPResolver(baseURL, apiKey string) *HTTPResolver {
	return &HTTPResolver{url: strings.TrimRight(baseURL, "/") + "/api/v1/permission-resolutions", apiKey: apiKey,
		timeout: 3 * time.Second, client: &http.Client{}}
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

// String names the resolver without its API key.
func (r *HTTPResolver) String() string {
	if r == nil {
		return "verify.HTTPResolver(nil)"
	}
	return fmt.Sprintf("verify.HTTPResolver{URL:%q APIKey:%s}", r.url, redacted(r.apiKey))
}

// GoString is String.
func (r *HTTPResolver) GoString() string { return r.String() }

type resolveRequest struct {
	PrincipalType  string `json:"principal_type"`
	PrincipalID    string `json:"principal_id"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Service        string `json:"service"`
	ActAs          bool   `json:"act_as,omitempty"`
	PermsRef       string `json:"perms_ref"`
}

type resolveResponse struct {
	Match       bool     `json:"match"`
	Permissions []string `json:"permissions"`
}

// Resolve implements PermissionResolver. Any error, including a timeout or a non-200 answer, means the answer
// could not be had; the request is then refused with 503. The key is never part of an error.
func (r *HTTPResolver) Resolve(ctx context.Context, claims *Claims) ([]string, bool, error) {
	if err := r.validate(false); err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	typ := "PRINCIPAL_TYPE_USER"
	if claims.IsServiceAccount() {
		typ = "PRINCIPAL_TYPE_SERVICE_ACCOUNT"
	}
	service := ""
	if len(claims.Audience) == 1 {
		service = claims.Audience[0]
	}
	body, err := json.Marshal(resolveRequest{PrincipalType: typ, PrincipalID: claims.Subject, OrganizationID: claims.OrgID,
		ProjectID: claims.ProjectID, Service: service, ActAs: claims.IsActAs(), PermsRef: claims.PermsRef})
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "ApiKey "+r.apiKey)
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
