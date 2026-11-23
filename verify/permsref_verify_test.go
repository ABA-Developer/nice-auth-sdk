package verify

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	// vRef is the reference of vRefPerms, computed outside Go (see permsref_test.go).
	vRef      = "v1.yjU-1od_cR396xnlHYSnnxaMGlfmFXDxS0Xa1LqrBGs"
	vOtherRef = "v1.l3sv8xPdHa4nb-xc9GBOXi2N7YujDvvk9tR00D7z_y4"
)

var vRefPerms = []string{"navi.orders.read", "navi.routes.read"}

func vectorNow() time.Time { return time.Unix(vNow, 0) }

// refusal returns err as the refusal the verifier answers with, or an empty one when err is something else.
func refusal(err error) Error {
	var e *Error
	if errors.As(err, &e) {
		return *e
	}
	return Error{}
}

// refClaims builds the claims of a token that carries perms_ref instead of perms.
func refClaims(over map[string]any) map[string]any {
	c := map[string]any{"perms": nil, "perms_ref": vRef}
	for k, v := range over {
		c[k] = v
	}
	return claims(c)
}

func TestATokenWithPermsAndPermsRefIsMalformed(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	v := fixedVerifier(t, s, 30*time.Minute, vectorNow, nil)
	for name, perms := range map[string]any{"a list": []string{"navi.orders.read"}, "an empty list": []string{}} {
		_, err := v.Verify(context.Background(), s.sign(t, claims(map[string]any{"perms": perms, "perms_ref": vRef})))
		if e := refusal(err); e.Status != 401 || e.Code != "invalid_token" || e.Description != ReasonMalformed {
			t.Errorf("perms as %s next to perms_ref: %v", name, err)
		}
	}
}
