package credentials

import (
	"errors"
	"fmt"
)

// ErrSessionEnded is returned (wrapped in a GrantError) when NICE ended the
// session or refused the credentials for good: the application must ask the
// user to connect again, or fix the key. The SDK does not retry it.
var ErrSessionEnded = errors.New("niceauth: session ended")

// ErrNotConnected is returned for a subject that has no refresh token.
var ErrNotConnected = errors.New("niceauth: not connected to NICE")

// GrantError is an answer of the token endpoint that refused the request.
type GrantError struct {
	Status      int
	Code        string
	Description string
	// Permanent is true for invalid_grant, invalid_client and unauthorized_client.
	Permanent bool
}

func (e *GrantError) Error() string {
	return fmt.Sprintf("niceauth: token endpoint refused (%d %s): %s", e.Status, e.Code, e.Description)
}

// Is makes errors.Is(err, ErrSessionEnded) true for a permanent refusal.
func (e *GrantError) Is(target error) bool { return target == ErrSessionEnded && e.Permanent }

// TemporaryError is a failure to get an answer from NICE (network, 5xx, 429): worth retrying later.
type TemporaryError struct{ Err error }

func (e *TemporaryError) Error() string { return "niceauth: NICE did not answer: " + e.Err.Error() }
func (e *TemporaryError) Unwrap() error { return e.Err }

// IsTemporary reports whether err is a failure to reach NICE, not a refusal.
func IsTemporary(err error) bool {
	var t *TemporaryError
	return errors.As(err, &t)
}
