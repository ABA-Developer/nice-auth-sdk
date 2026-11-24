package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

var updateVectors = flag.Bool("update-vectors", false, "regenerate verify/testdata/vectors.json with a new key")

const (
	vIssuer   = "https://auth.example.test"
	vService  = "navi"
	vOrg      = "org_01a17b49-56bc-7632-a32f-d47311c068c1"
	vOrg2     = "org_01a17b49-9999-7632-a32f-d47311c068c1"
	vProject  = "prj_01a17b4d-60ec-7555-853c-3e3a50f76435"
	vProject2 = "prj_01a17b4d-7777-7555-853c-3e3a50f76435"
	vUser     = "usr_01a17b4e-1111-7000-8000-000000000001"
	vSA       = "sa_01a17b4e-2222-7000-8000-000000000002"
	vPlatform = "org_00000000-0000-7000-8000-000000000001"
	vNow      = int64(1793329000) // 2026-10-30
)

type signer struct {
	key *rsa.PrivateKey
	kid string
}

func (s signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := sg.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// claims builds the claims of a token for the service, issued ten minutes before vNow.
func claims(over map[string]any) map[string]any {
	c := map[string]any{"iss": vIssuer, "sub": vUser, "aud": vService, "iat": vNow - 600, "exp": vNow - 600 + 1800, "jti": "0192f3a4-7b1c-7d2e-9a10-3c5f6e7d8a90",
		"scope": "nice:aud:navi nice:prj:" + vProject, "azp": "console", "nice_org_id": vOrg, "nice_principal_type": "user", "prj": vProject,
		"perms": []string{"navi.orders.read"}, "pv": 12}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// TestWriteVectors writes the shared vectors. It runs only with -update-vectors,
// because every run makes a new key and the file is reviewed and committed.
// Vectors already in the file are kept as they are, so other implementations
// keep their fixtures; only new vectors are signed, with a new key added to the
// JWKS. Delete the file to sign every vector again with one key.
func TestWriteVectors(t *testing.T) {
	if !*updateVectors {
		t.Skip("run with -update-vectors to regenerate verify/testdata/vectors.json")
	}
	gen := func() signer {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return signer{key: k, kid: "vector-key-1"}
	}
	good, other := gen(), gen()
	other.kid = "vector-key-unknown"
	var kept vectorFile
	var keys jose.JSONWebKeySet
	if raw, err := os.ReadFile(vectorsPath); err == nil {
		if err := json.Unmarshal(raw, &kept); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(kept.JWKS, &keys); err != nil {
			t.Fatal(err)
		}
		good.kid = "vector-key-" + itoa(int64(len(keys.Keys)+1))
	}
	keys.Keys = append(keys.Keys, publicJWK(good))
	jwks, _ := json.Marshal(keys)

	valid := good.sign(t, claims(nil))
	// Tamper with the payload of a valid token: the signature no longer matches.
	forged := splitReplace(valid, 1, b64([]byte(`{"iss":"`+vIssuer+`","sub":"`+vUser+`","aud":"`+vService+`","iat":`+itoa(vNow-600)+`,"exp":`+itoa(vNow+9999)+`,"nice_org_id":"`+vOrg+`","prj":"`+vProject+`","perms":["navi.admin.all"]}`)))
	none := b64([]byte(`{"alg":"none","typ":"JWT","kid":"vector-key-1"}`)) + "." + b64(mustJSON(claims(nil))) + "."
	hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("secret-that-is-at-least-32-bytes-long!!")}, (&jose.SignerOptions{}).WithHeader("kid", good.kid))
	if err != nil {
		t.Fatal(err)
	}
	hsJWS, _ := hs.Sign(mustJSON(claims(nil)))
	hsTok, _ := hsJWS.CompactSerialize()

	actAs := good.sign(t, claims(map[string]any{"nice_act_as": vPlatform}))
	byRef := good.sign(t, refClaims(nil))

	read := vectorRequest{Permission: "navi.orders.read"}
	ok200 := vectorExpect{Status: 200, Tenant: vOrg}
	deny := func(status int, code, desc string) vectorExpect {
		return vectorExpect{Status: status, Error: code, Description: desc}
	}
	allowAll := vectorTenant{Policy: "allow_all"}
	vs := []vector{
		{Name: "valid_user_token", Description: "a token for this service, project and permission", Token: valid, Now: vNow, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "valid_service_account_token", Description: "a Service Account token is verified like a user token",
			Token: good.sign(t, claims(map[string]any{"sub": vSA, "nice_principal_type": "service_account"})), Now: vNow, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "expired", Description: "exp is past by more than the skew", Token: good.sign(t, claims(map[string]any{"exp": vNow - 61})), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "expired")},
		{Name: "within_skew", Description: "exp is past by less than the skew of 60 seconds", Token: good.sign(t, claims(map[string]any{"exp": vNow - 30})), Now: vNow, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "not_yet_valid", Description: "nbf lies in the future by more than the skew", Token: good.sign(t, claims(map[string]any{"nbf": vNow + 300})), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "not_yet_valid")},
		{Name: "wrong_audience", Description: "the token is for another service", Token: good.sign(t, claims(map[string]any{"aud": "nadi"})), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "wrong_audience")},
		{Name: "two_audiences", Description: "a token with more than one audience is refused even if this service is one of them", Token: good.sign(t, claims(map[string]any{"aud": []string{vService, "nadi"}})), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "wrong_audience")},
		{Name: "wrong_issuer", Description: "iss is not the issuer of NICE", Token: good.sign(t, claims(map[string]any{"iss": "https://evil.example.test"})), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "wrong_issuer")},
		{Name: "alg_none", Description: "an unsigned token", Token: none, Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "algorithm_not_allowed")},
		{Name: "alg_hs256", Description: "a token signed with HMAC; only RS256 is allowed", Token: hsTok, Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "algorithm_not_allowed")},
		{Name: "unknown_kid", Description: "signed by a key that is not in the JWKS", Token: other.sign(t, claims(nil)), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "unknown_key")},
		{Name: "bad_signature", Description: "the payload was changed after signing", Token: forged, Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "bad_signature")},
		{Name: "malformed", Description: "not a JWT", Token: "not-a-token", Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "malformed")},
		{Name: "missing_token", Description: "no Authorization header", Token: "", Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "missing_token")},
		{Name: "permission_missing", Description: "the token does not hold the permission the operation needs", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.delete"}, Tenant: allowAll, Expect: deny(403, "insufficient_scope", "permission_denied")},
		{Name: "project_mismatch", Description: "the request names another project than the token", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.read", Project: vProject2}, Tenant: allowAll, Expect: deny(403, "insufficient_scope", "project_mismatch")},
		{Name: "project_matches", Description: "the request names the project of the token", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.read", Project: vProject}, Tenant: allowAll, Expect: ok200},
		{Name: "stale_principal", Description: "the principal was disabled after the token was issued", Token: valid, Now: vNow,
			Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg, Kind: "principal_disabled", OccurredAt: vNow - 120}}, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "issued_after_change", Description: "the change is older than the token", Token: valid, Now: vNow,
			Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg, Kind: "principal_disabled", OccurredAt: vNow - 900}}, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "stale_organization", Description: "the organization was suspended after the token was issued", Token: valid, Now: vNow,
			Changes: []vectorChange{{OrganizationID: vOrg, Kind: "org_state_changed", OccurredAt: vNow - 120}}, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "stale_project", Description: "the project changed after the token was issued", Token: valid, Now: vNow,
			Changes: []vectorChange{{OrganizationID: vOrg, ProjectID: vProject, Kind: "project_state_changed", OccurredAt: vNow - 120}}, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "change_of_another_principal", Description: "a change concerning someone else does not touch this token", Token: valid, Now: vNow,
			Changes: []vectorChange{{PrincipalID: "usr_01a17b4e-3333-7000-8000-000000000003", OrganizationID: vOrg, Kind: "member_removed", OccurredAt: vNow - 120}}, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "change_in_another_organization", Description: "a change of the same principal in another organization does not touch this token", Token: valid, Now: vNow,
			Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg2, Kind: "member_removed", OccurredAt: vNow - 120}}, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "sensitive_allowed", Description: "a sensitive operation passes when the online check allows it", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.read", Sensitive: true}, Check: "allow", Tenant: allowAll, Expect: ok200},
		{Name: "sensitive_denied", Description: "a sensitive operation is refused when the online check denies it", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.read", Sensitive: true}, Check: "deny", Tenant: allowAll, Expect: deny(403, "insufficient_scope", "access_denied")},
		{Name: "sensitive_check_down", Description: "a sensitive operation fails closed when NICE cannot be reached", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.read", Sensitive: true}, Check: "down", Tenant: allowAll, Expect: deny(503, "temporarily_unavailable", "access_check_unavailable")},
		{Name: "organization_rejected", Description: "the service accepts only the organizations on its list", Token: valid, Now: vNow, Request: read, Tenant: vectorTenant{Policy: "allow_list", Orgs: []string{vOrg2}}, Expect: deny(403, "insufficient_scope", "org_rejected")},
		{Name: "organization_listed", Description: "the organization is on the list of the service", Token: valid, Now: vNow, Request: read, Tenant: vectorTenant{Policy: "allow_list", Orgs: []string{vOrg}}, Expect: ok200},
		{Name: "organization_created_on_first_use", Description: "a service that creates tenants on first use accepts a new organization", Token: valid, Now: vNow, Request: read, Tenant: vectorTenant{Policy: "provision"}, Expect: ok200},
		{Name: "tenant_from_client_ignored", Description: "the tenant is the organization of the token, never what the client asks for", Token: valid, Now: vNow, Request: vectorRequest{Permission: "navi.orders.read", ClientTenant: vOrg2}, Tenant: allowAll, Expect: ok200},
		{Name: "valid_exchanged_token", Description: "a token a service backend got by token exchange: accepted like any other, the handler sees the user as subject and act.sub as actor",
			Token: good.sign(t, claims(map[string]any{"act": map[string]any{"sub": "naia-backend"}, "azp": "naia-backend"})), Now: vNow, Request: read, Tenant: allowAll,
			Expect: vectorExpect{Status: 200, Tenant: vOrg, Actor: "naia-backend"}},
		{Name: "expired_exchanged_token", Description: "a token from a token exchange whose exp is past is refused for its expiry, act changes nothing",
			Token: good.sign(t, claims(map[string]any{"act": map[string]any{"sub": "naia-backend"}, "azp": "naia-backend", "exp": vNow - 61})), Now: vNow, Request: read,
			Tenant: allowAll, Expect: deny(401, "invalid_token", "expired")},
		{Name: "valid_act_as_token", Description: "a token of a platform operator acting in an organization it is not a member of: accepted like any other, the handler sees nice_act_as",
			Token: actAs, Now: vNow, Request: read, Tenant: allowAll, Expect: vectorExpect{Status: 200, Tenant: vOrg, ActAs: vPlatform}},
		{Name: "stale_act_as_operator", Description: "a token act-as is stale after a change of its principal in the organization nice_act_as names",
			Token: actAs, Now: vNow, Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vPlatform, Kind: "binding_deleted", OccurredAt: vNow - 120}},
			Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "change_in_platform_without_act_as", Description: "a change of the principal in the platform organization does not touch a token without nice_act_as",
			Token: valid, Now: vNow, Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vPlatform, Kind: "binding_deleted", OccurredAt: vNow - 120}},
			Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "lifetime_exceeds_ttl", Description: "the token lives longer than the TTL plus the skew: a change that revoked it would be forgotten before it expires",
			Token: good.sign(t, claims(map[string]any{"exp": vNow - 600 + 3600})), Now: vNow, Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_lifetime_exceeded")},
		{Name: "missing_iat", Description: "a token without iat: its lifetime cannot be checked", Token: good.sign(t, claims(map[string]any{"iat": nil})), Now: vNow, Request: read,
			Tenant: allowAll, Expect: deny(401, "invalid_token", "token_lifetime_exceeded")},
		{Name: "stale_same_second_by_policy_version", Description: "the change came in the second the token was issued, with a higher policy version than pv",
			Token: valid, Now: vNow, Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg, Kind: "binding_deleted", OccurredAt: vNow - 600, PolicyVersion: 13}},
			Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "issued_after_change_same_second", Description: "the token was issued after the change, in the same second: pv equals the version of the change",
			Token: good.sign(t, claims(map[string]any{"pv": 13})), Now: vNow,
			Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg, Kind: "binding_deleted", OccurredAt: vNow - 600, PolicyVersion: 13}}, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "policy_version_other_org", Description: "a higher policy version of another organization does not touch the token",
			Token: valid, Now: vNow, Changes: []vectorChange{{OrganizationID: vOrg2, Kind: "role_changed", OccurredAt: vNow - 600, PolicyVersion: 50}},
			Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "stale_act_as_same_second", Description: "the operator role was removed in the platform organization in the second the token act-as was issued",
			Token: actAs, Now: vNow, Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vPlatform, Kind: "binding_deleted", OccurredAt: vNow - 600, PolicyVersion: 40}},
			Request: read, Tenant: allowAll, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "stale_without_pv", Description: "a token without pv is judged by the second it was issued",
			Token: good.sign(t, claims(map[string]any{"pv": nil})), Now: vNow,
			Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg, Kind: "binding_deleted", OccurredAt: vNow - 599, PolicyVersion: 13}}, Request: read, Tenant: allowAll,
			Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "same_second_without_pv", Description: "a token without pv of the second of the change is not refused: only pv can order them",
			Token: good.sign(t, claims(map[string]any{"pv": nil})), Now: vNow,
			Changes: []vectorChange{{PrincipalID: vUser, OrganizationID: vOrg, Kind: "binding_deleted", OccurredAt: vNow - 600, PolicyVersion: 13}}, Request: read, Tenant: allowAll, Expect: ok200},
		{Name: "perms_ref_resolved", Description: "a token that carries perms_ref instead of perms: the list NICE resolves it to holds the permission",
			Token: byRef, Now: vNow, Request: read, Tenant: allowAll, Resolve: &vectorResolve{Answer: "match", Permissions: vRefPerms}, Expect: ok200},
		{Name: "perms_ref_permission_missing", Description: "the list perms_ref names does not hold the permission the operation needs",
			Token: byRef, Now: vNow, Request: vectorRequest{Permission: "navi.orders.delete"}, Tenant: allowAll,
			Resolve: &vectorResolve{Answer: "match", Permissions: vRefPerms}, Expect: deny(403, "insufficient_scope", "permission_denied")},
		{Name: "perms_ref_mismatch", Description: "NICE says perms_ref no longer matches the permissions of the principal: the token is stale",
			Token: byRef, Now: vNow, Request: read, Tenant: allowAll, Resolve: &vectorResolve{Answer: "mismatch"}, Expect: deny(401, "invalid_token", "token_stale")},
		{Name: "perms_ref_resolution_down", Description: "perms_ref is not known and NICE cannot be reached: the request fails closed",
			Token: byRef, Now: vNow, Request: read, Tenant: allowAll, Resolve: &vectorResolve{Answer: "down"},
			Expect: deny(503, "temporarily_unavailable", "permissions_unavailable")},
		{Name: "perms_ref_other_list", Description: "the answer holds a list whose reference is not perms_ref: it is not used, even though it holds the permission",
			Token: byRef, Now: vNow, Request: read, Tenant: allowAll, Resolve: &vectorResolve{Answer: "match", Permissions: []string{"navi.orders.read"}},
			Expect: deny(503, "temporarily_unavailable", "permissions_unavailable")},
		{Name: "perms_and_perms_ref", Description: "a token that carries both perms and perms_ref says its permissions twice and is refused",
			Token: good.sign(t, claims(map[string]any{"perms_ref": vRef})), Now: vNow, Request: read, Tenant: allowAll,
			Resolve: &vectorResolve{Answer: "match", Permissions: vRefPerms}, Expect: deny(401, "invalid_token", "malformed")},
	}
	if len(kept.Vectors) > 0 {
		vs = keepVectors(kept.Vectors, vs)
	}
	// The references are literals computed outside this package, so a wrong PermsRef cannot write its own answer.
	refs := []vectorPermsRef{
		{Permissions: []string{"navi.routes.read", "navi.orders.read", "navi.orders.read"}, PermsRef: vRef},
		{Permissions: []string{"b.x.read", "a.y.edit"}, PermsRef: vThirdRef},
		{Permissions: []string{}, PermsRef: "v1.47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"},
	}
	out := vectorFile{Version: 3, Issuer: vIssuer, Service: vService, JWKS: jwks, Vectors: vs, PermsRefs: refs}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// keepVectors returns made in its order, each vector replaced by the one of the same name in kept when there is one.
func keepVectors(kept, made []vector) []vector {
	byName := map[string]vector{}
	for _, v := range kept {
		byName[v.Name] = v
	}
	out := make([]vector, len(made))
	for i, v := range made {
		if k, ok := byName[v.Name]; ok {
			v = k
		}
		out[i] = v
	}
	return out
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func itoa(n int64) string { return string(mustJSON(n)) }

func splitReplace(tok string, part int, with string) string {
	parts := [3]string{}
	i, last := 0, 0
	for j := 0; j <= len(tok); j++ {
		if j == len(tok) || tok[j] == '.' {
			parts[i] = tok[last:j]
			i, last = i+1, j+1
		}
	}
	parts[part] = with
	return parts[0] + "." + parts[1] + "." + parts[2]
}

func publicJWK(s signer) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}
}
