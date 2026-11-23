package verify

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// maxResolutionWait bounds a resolution whatever the resolver does, since it outlives the request that started it.
const maxResolutionWait = 30 * time.Second

var (
	errResolutionMismatch = errors.New("niceauth: the resolved permissions are not the ones perms_ref names")
	errNoResolver         = errors.New("niceauth: Config.Resolver is not set")
	errUnknownPermsRef    = errors.New("niceauth: perms_ref is of a version this verifier does not know")
)

// resolvePermissions fills c.Permissions of a token that carries perms_ref, or says why it cannot.
func (v *Verifier) resolvePermissions(ctx context.Context, c *Claims) *Error {
	down := func(err error) *Error {
		v.warnResolution(err)
		return unavailable("temporarily_unavailable", ReasonPermsDown)
	}
	if c.TokenID != "" && v.perms.isStale(c.TokenID) {
		return invalid(ReasonStale)
	}
	if !strings.HasPrefix(c.PermsRef, permsRefV1) {
		return down(errUnknownPermsRef)
	}
	if perms, ok := v.perms.get(c.PermsRef); ok {
		c.Permissions = perms
		return nil
	}
	// A mismatch is the answer for one principal, so the principal is part of the key. The call does not end with
	// the request that started it: the requests waiting for its answer are still there.
	key := strings.Join([]string{c.Subject, c.OrgID, c.ProjectID, c.ActAs, c.PermsRef}, "\x00")
	res := v.perms.once(ctx, key, func() resolution {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), maxResolutionWait)
		defer cancel()
		if perms, ok := v.perms.fromStore(rctx, c.PermsRef); ok {
			return resolution{permissions: perms, match: true}
		}
		if v.cfg.Resolver == nil {
			return resolution{err: errNoResolver}
		}
		perms, match, err := v.cfg.Resolver.Resolve(rctx, c)
		switch {
		case err != nil:
			return resolution{err: err}
		case !match:
			return resolution{}
		case PermsRef(perms) != c.PermsRef:
			return resolution{err: errResolutionMismatch}
		}
		v.perms.keep(rctx, c.PermsRef, perms)
		return resolution{permissions: perms, match: true}
	})
	switch {
	case res.err != nil:
		return down(res.err)
	case !res.match:
		if c.TokenID != "" {
			v.perms.markStale(c.TokenID, c.ExpiresAt, v.cfg.Now().Unix())
		}
		return invalid(ReasonStale)
	}
	c.Permissions = slices.Clone(res.permissions)
	return nil
}

// warnResolution logs why a perms_ref could not be resolved, at most once a minute: the cause is a NICE that is
// down or a service that is not configured, which every such token meets again.
func (v *Verifier) warnResolution(err error) {
	now := v.cfg.Now().UnixNano()
	last := v.resolutionWarned.Load()
	if last != 0 && now-last < int64(time.Minute) {
		return
	}
	if !v.resolutionWarned.CompareAndSwap(last, now) {
		return
	}
	v.cfg.Log.Warn("niceauth: the permissions of a token with perms_ref could not be resolved; the request was refused with 503",
		slog.String("error", err.Error()))
}
