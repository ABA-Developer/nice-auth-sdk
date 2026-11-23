package verify

import (
	"context"
	"strings"
)

// resolvePermissions fills c.Permissions of a token that carries perms_ref, or says why it cannot.
func (v *Verifier) resolvePermissions(ctx context.Context, c *Claims) *Error {
	down := unavailable("temporarily_unavailable", ReasonPermsDown)
	if c.TokenID != "" && v.perms.isStale(c.TokenID) {
		return invalid(ReasonStale)
	}
	if !strings.HasPrefix(c.PermsRef, permsRefV1) {
		return down
	}
	if perms, ok := v.perms.get(c.PermsRef); ok {
		c.Permissions = perms
		return nil
	}
	if v.cfg.Resolver == nil {
		return down
	}
	perms, match, err := v.cfg.Resolver.Resolve(ctx, c)
	switch {
	case err != nil:
		return down
	case !match:
		if c.TokenID != "" {
			v.perms.markStale(c.TokenID, c.ExpiresAt, v.cfg.Now().Unix())
		}
		return invalid(ReasonStale)
	case PermsRef(perms) != c.PermsRef:
		return down
	}
	v.perms.put(c.PermsRef, perms)
	c.Permissions = perms
	return nil
}
