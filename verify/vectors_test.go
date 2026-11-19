package verify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// The vectors are the shared proof of the verification contract: every
// implementation, in any language, must give these answers. See docs/token-verification.md.
const vectorsPath = "testdata/vectors.json"

type vectorFile struct {
	Version int             `json:"version"`
	Issuer  string          `json:"issuer"`
	Service string          `json:"service"`
	JWKS    json.RawMessage `json:"jwks"`
	Vectors []vector        `json:"vectors"`
}

type vector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Token       string `json:"token"`
	// Now is the clock of the verifier, in Unix seconds.
	Now     int64         `json:"now"`
	Request vectorRequest `json:"request"`
	// Changes are access changes the service received from the feed before the request.
	Changes []vectorChange `json:"changes,omitempty"`
	Tenant  vectorTenant   `json:"tenant"`
	// Check is the answer of the online access check: allow, deny or down.
	Check  string       `json:"check,omitempty"`
	Expect vectorExpect `json:"expect"`
}

type vectorRequest struct {
	Permission string `json:"permission"`
	// Project is the project the request names, if it names one.
	Project   string `json:"project,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
	// ClientTenant is a tenant the client claims in its request; it must never be used.
	ClientTenant string `json:"client_tenant,omitempty"`
}

type vectorChange struct {
	PrincipalID    string `json:"principal_id,omitempty"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id,omitempty"`
	Kind           string `json:"kind"`
	OccurredAt     int64  `json:"occurred_at"`
}

type vectorTenant struct {
	// Policy is allow_all, allow_list or provision.
	Policy string   `json:"policy"`
	Orgs   []string `json:"orgs,omitempty"`
}

type vectorExpect struct {
	Status      int    `json:"status"`
	Error       string `json:"error,omitempty"`
	Description string `json:"description,omitempty"`
	// Tenant is the tenant the handler saw.
	Tenant string `json:"tenant,omitempty"`
	// Actor is act.sub as the handler saw it: the client that exchanged the user's token for this one.
	Actor string `json:"actor,omitempty"`
	// ActAs is nice_act_as as the handler saw it: the platform organization of a platform operator acting here.
	ActAs string `json:"act_as,omitempty"`
}

type fakeChecker string

func (f fakeChecker) Check(context.Context, *Claims, string) (bool, error) {
	switch f {
	case "allow":
		return true, nil
	case "deny":
		return false, nil
	}
	return false, errors.New("NICE is down")
}

// run sends the request of v through a verifier built the way the contract describes.
func (v vector) run(t *testing.T, f vectorFile) (int, map[string]string) {
	t.Helper()
	cfg := Config{Issuer: f.Issuer, Service: f.Service, StaticJWKS: f.JWKS, Now: func() time.Time { return time.Unix(v.Now, 0) },
		Skew: 60 * time.Second, TokenTTL: 30 * time.Minute}
	switch v.Tenant.Policy {
	case "allow_list":
		cfg.Tenants = AllowList(v.Tenant.Orgs...)
	case "provision":
		cfg.Tenants = ProvisionOnFirstUse(func(context.Context, string) error { return nil })
	case "allow_all":
		cfg.Tenants = OrgAsTenant()
	}
	if v.Check != "" {
		cfg.Checker = fakeChecker(v.Check)
	}
	ver, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ver.feed = &feedState{}
	for _, c := range v.Changes {
		ver.apply(feedPage{Changes: []feedChange{{OrganizationID: c.OrganizationID, PrincipalID: c.PrincipalID, ProjectID: c.ProjectID,
			Kind: c.Kind, OccurredAt: time.Unix(c.OccurredAt, 0).UTC().Format(time.RFC3339)}}})
	}
	var opts []RequireOption
	if v.Request.Project != "" {
		opts = append(opts, WithProject(func(r *http.Request) string { return r.Header.Get("X-Project-Id") }))
	}
	if v.Request.Sensitive {
		opts = append(opts, Sensitive())
	}
	h := ver.Middleware(ver.Require(v.Request.Permission, opts...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, _ := TenantFromContext(r.Context())
		c, _ := FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{"tenant": tenant, "actor": c.Actor, "act_as": c.ActAs})
	})))
	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	if v.Token != "" {
		req.Header.Set("Authorization", "Bearer "+v.Token)
	}
	if v.Request.Project != "" {
		req.Header.Set("X-Project-Id", v.Request.Project)
	}
	if v.Request.ClientTenant != "" {
		req.Header.Set("X-Tenant", v.Request.ClientTenant)
		req.URL.RawQuery = "tenant=" + v.Request.ClientTenant
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := map[string]string{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("the shared vectors are missing (generate them with -update-vectors): %v", err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Vectors) < 32 {
		t.Fatalf("vector file: version %d, %d vectors", f.Version, len(f.Vectors))
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			status, body := v.run(t, f)
			if status != v.Expect.Status {
				t.Fatalf("%s: status %d, want %d (%v)", v.Description, status, v.Expect.Status, body)
			}
			if v.Expect.Error != "" && (body["error"] != v.Expect.Error || body["error_description"] != v.Expect.Description) {
				t.Fatalf("%s: error %q/%q, want %q/%q", v.Description, body["error"], body["error_description"], v.Expect.Error, v.Expect.Description)
			}
			if v.Expect.Status == http.StatusOK && body["tenant"] != v.Expect.Tenant {
				t.Fatalf("%s: tenant %q, want %q", v.Description, body["tenant"], v.Expect.Tenant)
			}
			if v.Expect.Status == http.StatusOK && body["actor"] != v.Expect.Actor {
				t.Fatalf("%s: actor %q, want %q", v.Description, body["actor"], v.Expect.Actor)
			}
			if v.Expect.Status == http.StatusOK && body["act_as"] != v.Expect.ActAs {
				t.Fatalf("%s: act_as %q, want %q", v.Description, body["act_as"], v.Expect.ActAs)
			}
		})
	}
}
