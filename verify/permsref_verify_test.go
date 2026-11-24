package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
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

// fakeResolver answers resolutions from answer and records the claims of every call. With a gate it answers
// only once the gate is closed, or gives up when the context of the call ends.
type fakeResolver struct {
	mu     sync.Mutex
	calls  []Claims
	answer func(*Claims) ([]string, bool, error)
	gate   chan struct{}
}

func (f *fakeResolver) Resolve(ctx context.Context, c *Claims) ([]string, bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, *c)
	answer := f.answer
	f.mu.Unlock()
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
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
	v.deny.mark(FeedKey("p", vUser, vOrg2), FeedKey("o", vOrg2), 0, vectorNow(), vectorNow())
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

const (
	vUser2 = "usr_01a17b4e-3333-7000-8000-000000000003"
	// vThirdRef is the reference of vThirdPerms, computed outside Go (see permsref_test.go).
	vThirdRef = "v1.M8akJ-SX6NtB-NmmrCA-029nXXffK7dYwDwxzAq_zao"
)

var (
	vOtherPerms = []string{"navi.admin.all"}
	vThirdPerms = []string{"a.y.edit", "b.x.read"}
)

// byRef answers each reference with the list it names, as NICE does for a principal whose permissions did not change.
func byRef(c *Claims) ([]string, bool, error) {
	switch c.PermsRef {
	case vRef:
		return slices.Clone(vRefPerms), true, nil
	case vOtherRef:
		return slices.Clone(vOtherPerms), true, nil
	case vThirdRef:
		return slices.Clone(vThirdPerms), true, nil
	}
	return nil, false, nil
}

func mustVerify(t *testing.T, v *Verifier, token string) *Claims {
	t.Helper()
	c, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAReferenceIsResolvedOncePerHash(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: byRef}
	v := refVerifier(t, s, rs)
	first := s.sign(t, refClaims(nil))
	refreshed := s.sign(t, refClaims(map[string]any{"jti": "0192f3a4-7b1c-7d2e-9a10-000000000002", "iat": vNow - 60, "exp": vNow - 60 + 1800, "pv": 13}))
	other := s.sign(t, refClaims(map[string]any{"sub": vUser2, "nice_org_id": vOrg2, "prj": vProject2, "jti": "0192f3a4-7b1c-7d2e-9a10-000000000003"}))
	for name, token := range map[string]string{"the first request": first, "the same token again": first, "a token from a refresh": refreshed, "another principal": other} {
		if c := mustVerify(t, v, token); !c.Has("navi.orders.read") || !c.Has("navi.routes.read") {
			t.Errorf("%s: %+v", name, c.Permissions)
		}
	}
	if rs.count() != 1 {
		t.Fatalf("%d resolutions for one reference, want 1", rs.count())
	}
	if c := mustVerify(t, v, s.sign(t, refClaims(map[string]any{"perms_ref": vOtherRef}))); !c.Has("navi.admin.all") || c.Has("navi.orders.read") || rs.count() != 2 {
		t.Fatalf("another reference is resolved on its own: %+v after %d resolutions", c.Permissions, rs.count())
	}
}

func TestACachedReferenceIsServedWhileNICEIsDown(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: byRef}
	v := refVerifier(t, s, rs)
	token := s.sign(t, refClaims(nil))
	mustVerify(t, v, token)
	rs.set(down)
	if c := mustVerify(t, v, token); !c.Has("navi.orders.read") || rs.count() != 1 {
		t.Fatalf("the cached list is served without NICE: %+v after %d resolutions", c.Permissions, rs.count())
	}
	if _, err := v.Verify(context.Background(), s.sign(t, refClaims(map[string]any{"perms_ref": vOtherRef}))); refusal(err).Description != ReasonPermsDown {
		t.Fatalf("a reference that is not cached still fails closed: %v", err)
	}
	if c := mustVerify(t, v, s.sign(t, claims(nil))); !c.Has("navi.orders.read") {
		t.Fatal("a token with perms does not depend on NICE")
	}
}

func TestTheCachedListCannotBeChangedThroughTheClaims(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	v := refVerifier(t, s, &fakeResolver{answer: byRef})
	token := s.sign(t, refClaims(nil))
	c := mustVerify(t, v, token)
	c.Permissions[0] = "navi.admin.all"
	if again := mustVerify(t, v, token); again.Has("navi.admin.all") || !again.Has("navi.orders.read") {
		t.Fatalf("a handler that changes its claims changed the cache: %v", again.Permissions)
	}
}

func TestThePermissionCacheIsBounded(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: byRef}
	v := refVerifier(t, s, rs, func(c *Config) { c.Permissions = NewPermissionCache(2) })
	tokenOf := func(ref string) string { return s.sign(t, refClaims(map[string]any{"perms_ref": ref})) }
	for _, ref := range []string{vRef, vOtherRef, vThirdRef} {
		mustVerify(t, v, tokenOf(ref))
	}
	if rs.count() != 3 {
		t.Fatalf("%d resolutions for three references", rs.count())
	}
	if c := mustVerify(t, v, tokenOf(vRef)); !c.Has("navi.orders.read") || rs.count() != 4 {
		t.Fatalf("the oldest reference was evicted and is resolved again: %d resolutions", rs.count())
	}
	if c := mustVerify(t, v, tokenOf(vThirdRef)); !c.Has("b.x.read") || rs.count() != 4 {
		t.Fatalf("the newest references stay: %d resolutions", rs.count())
	}
}

func TestVerifiersShareAPermissionCache(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: byRef}
	shared := NewPermissionCache(0)
	token := s.sign(t, refClaims(nil))
	for i := 0; i < 3; i++ {
		v := refVerifier(t, s, rs, func(c *Config) { c.Permissions = shared })
		if c := mustVerify(t, v, token); !c.Has("navi.orders.read") {
			t.Fatalf("verifier %d: %+v", i, c.Permissions)
		}
	}
	if rs.count() != 1 {
		t.Fatalf("%d resolutions over three verifiers that share a cache, want 1", rs.count())
	}
	mustVerify(t, refVerifier(t, s, rs), token)
	if rs.count() != 2 {
		t.Fatalf("a verifier with a cache of its own asks on its own: %d resolutions", rs.count())
	}
}

func staleRefusal(err error) bool {
	e := refusal(err)
	return e.Status == 401 && e.Code == "invalid_token" && e.Description == ReasonStale
}

func TestAStaleTokenIsRememberedByItsID(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: mismatching}
	v := refVerifier(t, s, rs)
	token := s.sign(t, refClaims(nil))
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(context.Background(), token); !staleRefusal(err) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if rs.count() != 1 {
		t.Fatalf("%d resolutions of one stale token, want 1", rs.count())
	}
	// The reference still names the permissions of another principal: its token is resolved on its own.
	rs.set(byRef)
	other := s.sign(t, refClaims(map[string]any{"sub": vUser2, "jti": "0192f3a4-7b1c-7d2e-9a10-000000000003"}))
	if c := mustVerify(t, v, other); !c.Has("navi.orders.read") || rs.count() != 2 {
		t.Fatalf("another token with the same reference: %+v after %d resolutions", c.Permissions, rs.count())
	}
	if _, err := v.Verify(context.Background(), token); !staleRefusal(err) || rs.count() != 2 {
		t.Fatalf("the stale token stays refused although its reference is now cached: %v after %d resolutions", err, rs.count())
	}
}

func TestAStaleTokenWithoutAnIDIsAskedAgain(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: mismatching}
	v := refVerifier(t, s, rs)
	token := s.sign(t, refClaims(map[string]any{"jti": nil}))
	for i := 0; i < 2; i++ {
		if _, err := v.Verify(context.Background(), token); !staleRefusal(err) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if rs.count() != 2 {
		t.Fatalf("%d resolutions: a token without jti cannot be remembered", rs.count())
	}
}

func TestTheMemoryOfStaleTokensIsBounded(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	rs := &fakeResolver{answer: mismatching}
	v := refVerifier(t, s, rs, func(c *Config) { c.Permissions = NewPermissionCache(1) })
	limit := staleTokensPerSet
	tokens := make([]string, limit+1)
	for i := range tokens {
		tokens[i] = s.sign(t, refClaims(map[string]any{"jti": "jti-" + itoa(int64(i)), "exp": vNow + 60 + int64(i)}))
		if _, err := v.Verify(context.Background(), tokens[i]); !staleRefusal(err) {
			t.Fatalf("token %d: %v", i, err)
		}
	}
	if rs.count() != limit+1 {
		t.Fatalf("%d resolutions for %d tokens", rs.count(), limit+1)
	}
	if _, err := v.Verify(context.Background(), tokens[limit]); !staleRefusal(err) || rs.count() != limit+1 {
		t.Fatalf("the newest token is remembered: %v after %d resolutions", err, rs.count())
	}
	if _, err := v.Verify(context.Background(), tokens[0]); !staleRefusal(err) || rs.count() != limit+2 {
		t.Fatalf("the token that expires first was forgotten and is asked again: %v after %d resolutions", err, rs.count())
	}
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConcurrentRequestsShareOneResolution(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	release := make(chan struct{})
	rs := &fakeResolver{answer: byRef, gate: release}
	v := refVerifier(t, s, rs)
	token := s.sign(t, refClaims(nil))
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := v.Verify(context.Background(), token)
			if err == nil && !c.Has("navi.orders.read") {
				err = errors.New("verified without the resolved permissions")
			}
			errs <- err
		}()
	}
	waitFor(t, "the first resolution", func() bool { return rs.count() >= 1 })
	time.Sleep(100 * time.Millisecond) // let the other requests reach the resolution
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if rs.count() != 1 {
		t.Fatalf("%d resolutions for %d concurrent requests, want 1", rs.count(), n)
	}
}

func TestConcurrentPrincipalsDoNotShareAnAnswer(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	release := make(chan struct{})
	rs := &fakeResolver{gate: release, answer: func(c *Claims) ([]string, bool, error) {
		if c.Subject == vUser {
			return nil, false, nil
		}
		return byRef(c)
	}}
	v := refVerifier(t, s, rs)
	changed := s.sign(t, refClaims(nil))
	unchanged := s.sign(t, refClaims(map[string]any{"sub": vUser2, "jti": "0192f3a4-7b1c-7d2e-9a10-000000000003"}))
	results := map[string]chan error{changed: make(chan error, 1), unchanged: make(chan error, 1)}
	for token, out := range results {
		go func() { _, err := v.Verify(context.Background(), token); out <- err }()
	}
	waitFor(t, "both resolutions", func() bool { return rs.count() == 2 })
	close(release)
	if err := <-results[changed]; !staleRefusal(err) {
		t.Fatalf("the principal whose permissions changed: %v", err)
	}
	if err := <-results[unchanged]; err != nil {
		t.Fatalf("the principal whose permissions did not change is not refused with the other: %v", err)
	}
}

func TestAWaitingRequestStopsWhenItsOwnContextEnds(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	rs := &fakeResolver{answer: byRef, gate: release}
	v := refVerifier(t, s, rs)
	token := s.sign(t, refClaims(nil))
	go func() { _, _ = v.Verify(context.Background(), token) }()
	waitFor(t, "the first resolution", func() bool { return rs.count() == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := v.Verify(ctx, token)
	if e := refusal(err); e.Status != 503 || e.Description != ReasonPermsDown {
		t.Fatalf("a request that gives up waiting fails closed: %v", err)
	}
	if time.Since(start) > time.Second || rs.count() != 1 {
		t.Fatalf("it waited %v and made %d resolutions", time.Since(start), rs.count())
	}
}

func TestAFailedResolutionIsLoggedAtMostOnceAMinute(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	now := time.Unix(vNow, 0)
	clock := func(c *Config) { c.Now = func() time.Time { return now }; c.Log = log }
	token := s.sign(t, refClaims(nil))

	v := refVerifier(t, s, nil, clock)
	for i := 0; i < 3; i++ {
		_, _ = v.Verify(context.Background(), token)
	}
	if n := strings.Count(logs.String(), "Config.Resolver"); n != 1 {
		t.Fatalf("a verifier without a resolver says so once, not per request: %d lines\n%s", n, logs.String())
	}
	now = now.Add(61 * time.Second)
	_, _ = v.Verify(context.Background(), token)
	if n := strings.Count(logs.String(), "Config.Resolver"); n != 2 {
		t.Fatalf("it says so again a minute later: %d lines", n)
	}

	logs.Reset()
	v = refVerifier(t, s, &fakeResolver{answer: down}, clock)
	_, _ = v.Verify(context.Background(), token)
	if !strings.Contains(logs.String(), "NICE is down") {
		t.Fatalf("the error of the resolver is logged: %s", logs.String())
	}
}

// memStore is a PermissionStore in memory that counts its calls and can be made to fail.
type memStore struct {
	mu         sync.Mutex
	m          map[string][]string
	gets, puts int
	fail       bool
}

func (m *memStore) Get(_ context.Context, ref string) ([]string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if m.fail {
		return nil, false, errors.New("the store is down")
	}
	perms, ok := m.m[ref]
	return slices.Clone(perms), ok, nil
}

func (m *memStore) Put(_ context.Context, ref string, perms []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.fail {
		return errors.New("the store is down")
	}
	if m.m == nil {
		m.m = map[string][]string{}
	}
	m.m[ref] = slices.Clone(perms)
	return nil
}

func (m *memStore) snapshot() (list []string, gets, puts int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.m[vRef]), m.gets, m.puts
}

func withStore(store PermissionStore) func(*Config) {
	return func(c *Config) { c.Permissions = NewPermissionCache(0).WithStore(store) }
}

func TestThePermissionStoreIsReadBeforeNICE(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	store := &memStore{m: map[string][]string{vRef: vRefPerms}}
	rs := &fakeResolver{answer: down}
	token := s.sign(t, refClaims(nil))
	for name, resolver := range map[string]PermissionResolver{"NICE down": rs, "no resolver": nil} {
		v := refVerifier(t, s, resolver, withStore(store))
		_, before, _ := store.snapshot()
		for i := 0; i < 3; i++ {
			if c := mustVerify(t, v, token); !c.Has("navi.orders.read") || !c.Has("navi.routes.read") {
				t.Fatalf("%s: the list of the store is the list of the token: %+v", name, c.Permissions)
			}
		}
		if _, gets, _ := store.snapshot(); gets != before+1 {
			t.Fatalf("%s: memory is in front of the store: %d reads for three requests", name, gets-before)
		}
	}
	if _, _, puts := store.snapshot(); rs.count() != 0 || puts != 0 {
		t.Fatalf("NICE was asked %d times and the store written %d times for a list the store had", rs.count(), puts)
	}
}

func TestAResolvedListIsWrittenToThePermissionStore(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	store := &memStore{}
	rs := &fakeResolver{answer: byRef}
	token := s.sign(t, refClaims(nil))
	mustVerify(t, refVerifier(t, s, rs, withStore(store)), token)
	if list, _, puts := store.snapshot(); puts != 1 || !slices.Equal(list, vRefPerms) {
		t.Fatalf("the store got %v in %d writes", list, puts)
	}
	rs.set(down)
	if c := mustVerify(t, refVerifier(t, s, rs, withStore(store)), token); !c.Has("navi.orders.read") || rs.count() != 1 {
		t.Fatalf("another process with the same store needs no NICE: %+v after %d resolutions", c.Permissions, rs.count())
	}
}

func TestAStoreValueThatIsNotTheReferencedListIsIgnored(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	store := &memStore{m: map[string][]string{vRef: {"navi.admin.all"}}}
	rs := &fakeResolver{answer: byRef}
	v := refVerifier(t, s, rs, withStore(store))
	token := s.sign(t, refClaims(nil))
	if c := mustVerify(t, v, token); c.Has("navi.admin.all") || !c.Has("navi.orders.read") || rs.count() != 1 {
		t.Fatalf("a store cannot give a token other permissions: %+v after %d resolutions", c.Permissions, rs.count())
	}
	if list, _, _ := store.snapshot(); !slices.Equal(list, vRefPerms) {
		t.Fatalf("the store now holds the list NICE gave: %v", list)
	}
	rs.set(down)
	store.mu.Lock()
	store.m[vOtherRef] = []string{"navi.orders.read"}
	store.mu.Unlock()
	if _, err := v.Verify(context.Background(), s.sign(t, refClaims(map[string]any{"perms_ref": vOtherRef}))); refusal(err).Description != ReasonPermsDown {
		t.Fatalf("with NICE down a wrong store value is still not used: %v", err)
	}
}

func TestAFailingPermissionStoreIsAMiss(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	store := &memStore{fail: true}
	rs := &fakeResolver{answer: byRef}
	v := refVerifier(t, s, rs, withStore(store))
	token := s.sign(t, refClaims(nil))
	for i := 0; i < 2; i++ {
		if c := mustVerify(t, v, token); !c.Has("navi.orders.read") {
			t.Fatalf("request %d: %+v", i, c.Permissions)
		}
	}
	if rs.count() != 1 {
		t.Fatalf("%d resolutions: the list is kept in memory although the store fails", rs.count())
	}
}
