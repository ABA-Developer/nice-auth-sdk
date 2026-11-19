package verify

import (
	"fmt"
	"net/http"
)

// Error is a refusal with the HTTP status the service answers.
type Error struct {
	Status int
	// Code is the OAuth error code: invalid_token, insufficient_scope, or a service error code.
	Code string
	// Description says why, e.g. token_stale; it never contains the token.
	Description string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Description) }

func invalid(desc string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "invalid_token", Description: desc}
}

func forbidden(desc string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Description: desc}
}

func unavailable(code, desc string) *Error {
	return &Error{Status: http.StatusServiceUnavailable, Code: code, Description: desc}
}

// Reasons of an invalid token, used as the description and as the metric label.
const (
	ReasonMalformed   = "malformed"
	ReasonAlgorithm   = "algorithm_not_allowed"
	ReasonUnknownKey  = "unknown_key"
	ReasonSignature   = "bad_signature"
	ReasonIssuer      = "wrong_issuer"
	ReasonAudience    = "wrong_audience"
	ReasonExpired     = "expired"
	ReasonNotYetValid = "not_yet_valid"
	ReasonLifetime    = "token_lifetime_exceeded"
	ReasonStale       = "token_stale"
	ReasonPermission  = "permission_denied"
	ReasonProject     = "project_mismatch"
	ReasonOrg         = "org_rejected"
	ReasonCheck       = "access_denied"
	ReasonCheckDown   = "access_check_unavailable"
	ReasonKeysDown    = "keys_unavailable"
)
