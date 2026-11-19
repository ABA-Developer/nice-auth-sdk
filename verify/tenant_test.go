package verify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestMapTenantsGivesAServiceWithTenantsOfItsOwnTheirTenant(t *testing.T) {
	r := MapTenants(map[string]string{vOrg: "tenant-17"})
	if got, err := r.Resolve(context.Background(), vOrg); err != nil || got != "tenant-17" {
		t.Fatalf("a mapped organization: %q %v", got, err)
	}
	if _, err := r.Resolve(context.Background(), vOrg2); !errors.Is(err, ErrUnknownOrg) {
		t.Fatalf("an unmapped organization is refused: %v", err)
	}
}

func TestProvisionOnFirstUseCreatesOnceAndRetriesAFailure(t *testing.T) {
	var calls atomic.Int32
	fail := true
	r := ProvisionOnFirstUse(func(context.Context, string) error {
		calls.Add(1)
		if fail {
			return errors.New("database busy")
		}
		return nil
	})
	if _, err := r.Resolve(context.Background(), vOrg); err == nil {
		t.Fatal("a failed creation is an error")
	}
	fail = false
	for i := 0; i < 3; i++ {
		if got, err := r.Resolve(context.Background(), vOrg); err != nil || got != vOrg {
			t.Fatalf("after the retry: %q %v", got, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("one failed call, one that worked, and none after: %d", calls.Load())
	}
}

func TestATenantFailureIsA503NotA403(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	v := liveVerifier(t, s, nil)
	v.cfg.Tenants = TenantFunc(func(context.Context, string) (string, error) { return "", errors.New("database down") })
	h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not reach the handler") }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenIssued(t, s, time.Now().Add(-time.Minute), nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a tenant store that fails is not the client's fault: %d", rec.Code)
	}
}
