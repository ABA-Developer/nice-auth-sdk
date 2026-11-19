package verify

import "context"

// AccessChecker asks NICE, at the moment of the request, whether the principal
// of a token holds a permission. Operations declared x-nice-sensitive use it, so
// they do not depend on the permissions the token carried when it was issued.
type AccessChecker interface {
	// Check returns whether c may use permission now. An error means the answer
	// could not be had, and the request is refused with 503 (fail closed).
	Check(ctx context.Context, c *Claims, permission string) (allowed bool, err error)
}
