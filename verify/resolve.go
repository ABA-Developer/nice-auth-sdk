package verify

import "context"

// PermissionResolver asks NICE for the permissions the perms_ref of a token stands for. A token too large to
// carry its permissions carries their reference instead; the verifier resolves it once and keeps the answer.
type PermissionResolver interface {
	// Resolve returns the permissions the principal of c holds on the service of the token when their reference
	// is c.PermsRef, and match false when NICE says it no longer is: the permissions changed since the token was
	// issued. An error means the answer could not be had, and the request is refused with 503 (fail closed).
	Resolve(ctx context.Context, c *Claims) (permissions []string, match bool, err error)
}
