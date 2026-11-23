package verify

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
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

// fakeResolver answers resolutions from answer and records the claims of every call.
type fakeResolver struct {
	mu     sync.Mutex
	calls  []Claims
	answer func(*Claims) ([]string, bool, error)
}

func (f *fakeResolver) Resolve(_ context.Context, c *Claims) ([]string, bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, *c)
	answer := f.answer
	f.mu.Unlock()
	return answer(c)
}

func (f *fakeResolver) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func (f *fakeResolver) set(answer func(*Claims) ([]string, bool, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

func matching(perms ...string) func(*Claims) ([]string, bool, error) {
	return func(*Claims) ([]string, bool, error) { return slices.Clone(perms), true, nil }
}

func mismatching(*Claims) ([]string, bool, error) { return nil, false, nil }

func down(*Claims) ([]string, bool, error) { return nil, false, errors.New("NICE is down") }

// refVerifier builds a verifier of the vector service at the vector time; a nil rs leaves it without a resolver.
func refVerifier(t *testing.T, s signer, rs PermissionResolver, mod ...func(*Config)) *Verifier {
	t.Helper()
	jwks, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(s)}})
	cfg := Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Now: vectorNow, Resolver: rs}
	for _, m := range mod {
		m(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestATokenWithPermsRefGetsItsPermissionsFromTheResolver(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: matching(vRefPerms...)}
	v := refVerifier(t, s, rs)
	c, err := v.Verify(context.Background(), s.sign(t, refClaims(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Has("navi.orders.read") || !c.Has("navi.routes.read") || c.Has("navi.orders.delete") || c.PermsRef != vRef {
		t.Fatalf("the handler sees the resolved permissions as those of the token: %+v", c)
	}
	if rs.count() != 1 {
		t.Fatalf("%d resolutions, want 1", rs.count())
	}
	if got := rs.calls[0]; got.Subject != vUser || got.OrgID != vOrg || got.ProjectID != vProject || got.PermsRef != vRef ||
		len(got.Audience) != 1 || got.Audience[0] != vService || got.IsActAs() {
		t.Fatalf("the resolver gets the coordinates of the token: %+v", got)
	}
}

func TestATokenActAsIsResolvedAsActAs(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: matching(vRefPerms...)}
	v := refVerifier(t, s, rs)
	if _, err := v.Verify(context.Background(), s.sign(t, refClaims(map[string]any{"nice_act_as": vPlatform}))); err != nil {
		t.Fatal(err)
	}
	if rs.count() != 1 || !rs.calls[0].IsActAs() || rs.calls[0].ActAs != vPlatform {
		t.Fatalf("the resolver sees nice_act_as: %+v", rs.calls)
	}
}

func TestWithoutAResolverATokenWithPermsRefIsRefusedWith503(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	v := refVerifier(t, s, nil)
	_, err := v.Verify(context.Background(), s.sign(t, refClaims(nil)))
	if e := refusal(err); e.Status != 503 || e.Code != "temporarily_unavailable" || e.Description != ReasonPermsDown {
		t.Fatalf("no resolver: %v", err)
	}
	if _, err := v.Verify(context.Background(), s.sign(t, claims(nil))); err != nil {
		t.Fatalf("a token with perms needs no resolver: %v", err)
	}
}

func TestAResolutionThatCannotBeHadFailsClosed(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	token := s.sign(t, refClaims(nil))
	for name, answer := range map[string]func(*Claims) ([]string, bool, error){
		"NICE is down":             down,
		"a list of another set":    matching("navi.admin.all"),
		"a list with one too many": matching(append(slices.Clone(vRefPerms), "navi.orders.delete")...),
		"a match without a list":   matching(),
	} {
		rs := &fakeResolver{answer: answer}
		v := refVerifier(t, s, rs)
		_, err := v.Verify(context.Background(), token)
		if e := refusal(err); e.Status != 503 || e.Code != "temporarily_unavailable" || e.Description != ReasonPermsDown {
			t.Errorf("%s: %v", name, err)
		}
		rs.set(matching(vRefPerms...))
		if c, err := v.Verify(context.Background(), token); err != nil || !c.Has("navi.orders.read") || c.Has("navi.admin.all") || c.Has("navi.orders.delete") {
			t.Errorf("%s: nothing of the bad answer is kept, the next request asks again: %v", name, err)
		}
	}
}

func TestAReferenceOfAnUnknownVersionFailsClosedWithoutAskingNICE(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: matching(vRefPerms...)}
	v := refVerifier(t, s, rs)
	for _, ref := range []string{"v2." + vRef[3:], vRef[3:], "v1"} {
		_, err := v.Verify(context.Background(), s.sign(t, refClaims(map[string]any{"perms_ref": ref})))
		if e := refusal(err); e.Status != 503 || e.Description != ReasonPermsDown {
			t.Errorf("perms_ref %q: %v", ref, err)
		}
	}
	if rs.count() != 0 {
		t.Fatalf("%d resolutions of a reference this verifier cannot check", rs.count())
	}
}

func TestATokenThatIsNotValidIsNotResolved(t *testing.T) {
	s, other := testSigner(t, "vector-key-1"), testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: matching(vRefPerms...)}
	v := refVerifier(t, s, rs)
	v.deny.mark("p:"+vUser+"|"+vOrg2, vOrg2, 0, vectorNow(), vectorNow())
	for name, token := range map[string]string{
		"bad signature":  other.sign(t, refClaims(nil)),
		"expired":        s.sign(t, refClaims(map[string]any{"exp": vNow - 61})),
		"wrong audience": s.sign(t, refClaims(map[string]any{"aud": "nadi"})),
		"stale":          s.sign(t, refClaims(map[string]any{"nice_org_id": vOrg2})),
	} {
		if _, err := v.Verify(context.Background(), token); refusal(err).Status != 401 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if rs.count() != 0 {
		t.Fatalf("%d resolutions for tokens that are refused anyway", rs.count())
	}
}

func TestAReferenceThatNoLongerMatchesMakesTheTokenStale(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: mismatching}
	v := refVerifier(t, s, rs)
	_, err := v.Verify(context.Background(), s.sign(t, refClaims(nil)))
	if e := refusal(err); e.Status != 401 || e.Code != "invalid_token" || e.Description != ReasonStale {
		t.Fatalf("mismatch: %v", err)
	}
}
