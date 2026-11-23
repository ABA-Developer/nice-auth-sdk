package verify

import (
	"context"
	"strings"
)

// resolvePermissions fills c.Permissions of a token that carries perms_ref, or says why it cannot.
func (v *Verifier) resolvePermissions(ctx context.Context, c *Claims) *Error {
	down := unavailable("temporarily_unavailable", ReasonPermsDown)
	if !strings.HasPrefix(c.PermsRef, permsRefV1) || v.cfg.Resolver == nil {
		return down
	}
	perms, match, err := v.cfg.Resolver.Resolve(ctx, c)
	switch {
	case err != nil:
		return down
	case !match:
		return invalid(ReasonStale)
	case PermsRef(perms) != c.PermsRef:
		return down
	}
	c.Permissions = perms
	return nil
}
