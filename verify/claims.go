package verify

import (
	"encoding/json"
	"slices"
	"time"
)

// Claims are the claims of a verified NICE access token.
type Claims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      audience `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	NotBefore     int64    `json:"nbf"`
	IssuedAt      int64    `json:"iat"`
	TokenID       string   `json:"jti"`
	Scope         string   `json:"scope"`
	OrgID         string   `json:"nice_org_id"`
	PrincipalType string   `json:"nice_principal_type"`
	// ProjectID, Permissions and PolicyVersion are set on tokens for a service.
	ProjectID     string   `json:"prj"`
	Permissions   []string `json:"perms"`
	PolicyVersion int64    `json:"pv"`
	// Actor is act.sub: the client_id of the service backend that exchanged the user's token for this one and
	// acts on behalf of Subject. Empty on a token the user's own client received. It changes no decision.
	Actor string `json:"-"`
	// ActAs is nice_act_as: the platform organization, where the right of a platform operator of this service was
	// decided, on a token of an organization the operator is not a member of. Empty on any other token.
	ActAs string `json:"nice_act_as"`
	// hasPV is whether the token carries pv; a token without it is checked by the time it was issued only.
	hasPV bool
}

// UnmarshalJSON reads the claims, lifts act.sub into Actor, and notes whether pv is present.
func (c *Claims) UnmarshalJSON(b []byte) error {
	type plain Claims
	var raw struct {
		plain
		Act *struct {
			Subject string `json:"sub"`
		} `json:"act"`
		// PV shadows plain.PolicyVersion, so a missing pv can be told from pv 0.
		PV *int64 `json:"pv"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*c = Claims(raw.plain)
	if raw.Act != nil {
		c.Actor = raw.Act.Subject
	}
	if raw.PV != nil {
		c.PolicyVersion, c.hasPV = *raw.PV, true
	}
	return nil
}

// Has reports whether the token grants permission.
func (c *Claims) Has(permission string) bool { return slices.Contains(c.Permissions, permission) }

// Issued is when the token was issued.
func (c *Claims) Issued() time.Time { return time.Unix(c.IssuedAt, 0) }

// IsActAs reports whether a platform operator of the service acts in OrgID without being a member of it.
func (c *Claims) IsActAs() bool { return c.ActAs != "" }

// IsServiceAccount reports whether the token is that of a Service Account.
func (c *Claims) IsServiceAccount() bool { return c.PrincipalType == "service_account" }

// audience accepts the string and array forms of aud.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	err := json.Unmarshal(b, &many)
	*a = many
	return err
}
