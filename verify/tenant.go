package verify

import (
	"context"
	"errors"
	"sync"
)

// ErrUnknownOrg is returned by a TenantResolver for an organization the service does not accept; the request is answered 403.
var ErrUnknownOrg = errors.New("niceauth: organization is not known to this service")

// TenantResolver decides how an organization of NICE becomes a tenant of the
// service. The organization comes from the verified token (nice_org_id) and
// never from the request. A service that does not separate data by tenant needs none.
type TenantResolver interface {
	// Resolve returns the tenant of org, ErrUnknownOrg to refuse it with 403, or another error (503).
	Resolve(ctx context.Context, org string) (tenant string, err error)
}

// TenantFunc adapts a function to a TenantResolver.
type TenantFunc func(ctx context.Context, org string) (string, error)

// Resolve implements TenantResolver.
func (f TenantFunc) Resolve(ctx context.Context, org string) (string, error) { return f(ctx, org) }

// OrgAsTenant accepts every organization and uses its ID as the tenant.
func OrgAsTenant() TenantResolver {
	return TenantFunc(func(_ context.Context, org string) (string, error) { return org, nil })
}

// AllowList accepts only the listed organizations (the service administrator
// registers them) and uses their IDs as the tenant.
func AllowList(orgs ...string) TenantResolver {
	set := make(map[string]struct{}, len(orgs))
	for _, o := range orgs {
		set[o] = struct{}{}
	}
	return TenantFunc(func(_ context.Context, org string) (string, error) {
		if _, ok := set[org]; !ok {
			return "", ErrUnknownOrg
		}
		return org, nil
	})
}

// MapTenants accepts the organizations of table and returns the tenant the
// service already has for each: the way for a service with tenants of its own.
func MapTenants(table map[string]string) TenantResolver {
	return TenantFunc(func(_ context.Context, org string) (string, error) {
		t, ok := table[org]
		if !ok {
			return "", ErrUnknownOrg
		}
		return t, nil
	})
}

// ProvisionOnFirstUse creates the tenant of an organization the first time a
// valid token names it. A token for this service already proves that NICE
// entitled the organization and activated the service in the project, so the
// first sight of an organization is a safe moment to create its tenant.
// create must be idempotent; a failure is retried on the next request.
func ProvisionOnFirstUse(create func(ctx context.Context, org string) error) TenantResolver {
	var mu sync.Mutex
	done := map[string]bool{}
	return TenantFunc(func(ctx context.Context, org string) (string, error) {
		mu.Lock()
		ok := done[org]
		mu.Unlock()
		if ok {
			return org, nil
		}
		if err := create(ctx, org); err != nil {
			return "", err
		}
		mu.Lock()
		done[org] = true
		mu.Unlock()
		return org, nil
	})
}
