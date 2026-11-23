package verify

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var errResolutionMismatch = errors.New("niceauth: the resolved permissions are not the ones perms_ref names")

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
	// A mismatch is the answer for one principal, so the principal is part of the key. The call does not end with
	// the request that started it: the requests waiting for its answer are still there.
	key := strings.Join([]string{c.Subject, c.OrgID, c.ProjectID, c.ActAs, c.PermsRef}, "\x00")
	res := v.perms.once(ctx, key, func() resolution {
		perms, match, err := v.cfg.Resolver.Resolve(context.WithoutCancel(ctx), c)
		switch {
		case err != nil:
			return resolution{err: err}
		case !match:
			return resolution{}
		case PermsRef(perms) != c.PermsRef:
			return resolution{err: errResolutionMismatch}
		}
		v.perms.put(c.PermsRef, perms)
		return resolution{permissions: perms, match: true}
	})
	switch {
	case res.err != nil:
		return down
	case !res.match:
		if c.TokenID != "" {
			v.perms.markStale(c.TokenID, c.ExpiresAt, v.cfg.Now().Unix())
		}
		return invalid(ReasonStale)
	}
	c.Permissions = slices.Clone(res.permissions)
	return nil
}
