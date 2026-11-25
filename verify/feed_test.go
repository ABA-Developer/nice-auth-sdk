package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// feedServer plays the access change feed of NICE.
type feedServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	changes []feedChange
	down    bool
	queries []string
	// auths is the Authorization header of every request; the feed takes none.
	auths []string
}

func newFeedServer(t *testing.T) *feedServer {
	f := &feedServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// changeKeys returns the key and the org key NICE gives a change recorded in org: of principal in org when there is
// one, else of project when there is one, else of org itself.
func changeKeys(org, principal, project string) (key, orgKey string) {
	orgKey = FeedKey("o", org)
	switch {
	case principal != "":
		return FeedKey("p", principal, org), orgKey
	case project != "":
		return FeedKey("j", project), orgKey
	}
	return orgKey, orgKey
}

func (f *feedServer) add(org, principal, project, kind string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, orgKey := changeKeys(org, principal, project)
	f.changes = append(f.changes, feedChange{Seq: strconv.Itoa(len(f.changes) + 1), Key: key, OrgKey: orgKey, Kind: kind,
		OccurredAt: at.UTC().Format(time.RFC3339Nano)})
}

func (f *feedServer) authorizations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.auths...)
}

func (f *feedServer) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func (f *feedServer) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func (f *feedServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.queries = append(f.queries, r.URL.RawQuery)
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	down := f.down
	f.mu.Unlock()
	if down {
		http.Error(w, "no", http.StatusInternalServerError)
		return
	}
	if _, sent := r.Header["Authorization"]; sent {
		http.Error(w, "the feed takes no credential", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit == 0 {
		limit = 500
	}
	wait, _ := strconv.Atoi(q.Get("wait_seconds"))
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		f.mu.Lock()
		var out []feedChange
		for _, c := range f.changes {
			seq, _ := strconv.Atoi(c.Seq)
			if s := q.Get("since"); s != "" {
				since, _ := time.Parse(time.RFC3339, s)
				at, _ := time.Parse(time.RFC3339Nano, c.OccurredAt)
				if at.Before(since) {
					continue
				}
			} else if after, _ := strconv.Atoi(q.Get("after_seq")); seq <= after {
				continue
			}
			if len(out) < limit {
				out = append(out, c)
			}
		}
		latest := len(f.changes)
		f.mu.Unlock()
		if len(out) > 0 || time.Now().After(deadline) {
			page := feedPage{Changes: out, Seq: strconv.Itoa(latest)}
			if len(out) > 0 {
				page.Seq = out[len(out)-1].Seq
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func liveVerifier(t *testing.T, s signer, obs Observer) *Verifier {
	t.Helper()
	jwks, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(s)}})
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Observer: obs, TokenTTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// tokenIssued signs a token for the user that was issued at the given time.
func tokenIssued(t *testing.T, s signer, at time.Time, over map[string]any) string {
	c := claims(map[string]any{"iat": at.Unix(), "exp": at.Add(30 * time.Minute).Unix()})
	for k, v := range over {
		c[k] = v
	}
	return s.sign(t, c)
}

func startFeed(t *testing.T, v *Verifier, f *feedServer, over func(*FeedConfig)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fc := FeedConfig{BaseURL: f.srv.URL, Wait: time.Second, MonitorEvery: 20 * time.Millisecond, SilentAfter: 400 * time.Millisecond,
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, HTTP: f.srv.Client()}
	if over != nil {
		over(&fc)
	}
	if err := v.StartFeed(ctx, fc); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func stale(v *Verifier, tok string) bool {
	_, err := v.Verify(context.Background(), tok)
	e, ok := err.(*Error)
	return ok && e.Description == ReasonStale
}

func TestAStartReplaysTheRecentChangesBeforeServing(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	now := time.Now()
	f.add(vOrg, vUser, "", "principal_disabled", now.Add(-5*time.Minute))
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	if !stale(v, tokenIssued(t, s, now.Add(-10*time.Minute), nil)) {
		t.Fatal("a token issued before the change must be refused as soon as StartFeed returns")
	}
	if _, err := v.Verify(context.Background(), tokenIssued(t, s, now.Add(-2*time.Minute), nil)); err != nil {
		t.Fatalf("a token issued after the change is fine: %v", err)
	}
	if first := f.seen()[0]; len(first) < 5 || first[:5] != "since" && first[:5] != "limit" {
		t.Fatalf("the start must ask for a window of time, not for a seq: %q", first)
	}
}

func TestAChangeAfterTheStartRefusesOlderTokensAtOnce(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	tok := tokenIssued(t, s, time.Now().Add(-10*time.Minute), nil)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("before the change: %v", err)
	}
	f.add(vOrg, vUser, "", "key_revoked", time.Now())
	eventually(t, "the live change reaches the verifier", 3*time.Second, func() bool { return stale(v, tok) })
	// The poll continued from the position it had, not from the start.
	q := f.seen()
	if last := q[len(q)-1]; !contains(last, "after_seq=") || contains(last, "since=") {
		t.Fatalf("polling continues after a seq: %q", last)
	}
	if v.FeedSeq() != 1 {
		t.Fatalf("position: %d", v.FeedSeq())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestAReplayLargerThanOnePageIsAppliedInFull(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	now := time.Now()
	for i := 0; i < 1500; i++ {
		f.add(vOrg2, "usr_other-"+strconv.Itoa(i), "", "member_removed", now.Add(-time.Minute))
	}
	f.add(vOrg, vUser, "", "principal_disabled", now.Add(-time.Minute)) // change 1501 lies on the second page
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	if !stale(v, tokenIssued(t, s, now.Add(-10*time.Minute), nil)) {
		t.Fatal("the change on the second page of the replay must be applied")
	}
}

func TestASilentFeedMakesTheVerifierDegradedAndNotDead(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	stats := &Stats{}
	v := liveVerifier(t, s, stats)
	startFeed(t, v, f, nil)
	eventually(t, "the feed is healthy", 2*time.Second, func() bool { return !v.Degraded() && stats.Snapshot()["feed_polls.ok"] > 0 })
	f.setDown(true)
	eventually(t, "the silent feed degrades the verifier", 3*time.Second, func() bool { return v.Degraded() })
	tok := tokenIssued(t, s, time.Now().Add(-10*time.Minute), nil)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("a degraded verifier still serves ordinary requests, bounded by the token lifetime: %v", err)
	}
	snap := stats.Snapshot()
	if snap["degraded"] != 1 || snap["feed_polls.failed"] == 0 {
		t.Fatalf("degradation is visible in the counters: %v", snap)
	}
	f.setDown(false)
	eventually(t, "the feed comes back", 5*time.Second, func() bool { return !v.Degraded() })
	if stats.Snapshot()["degraded"] != 0 || stats.Snapshot()["degraded_switches"] != 2 {
		t.Fatalf("degraded on, then off: %v", stats.Snapshot())
	}
}

func TestAFailedReplayIsRetriedUntilTheFeedAnswers(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	now := time.Now()
	f.add(vOrg, vUser, "", "principal_disabled", now.Add(-time.Minute))
	f.setDown(true)
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil) // the start does not fail
	tok := tokenIssued(t, s, now.Add(-10*time.Minute), nil)
	if stale(v, tok) {
		t.Fatal("nothing is known while the feed is down")
	}
	f.setDown(false)
	eventually(t, "the missed window is replayed once the feed answers", 3*time.Second, func() bool { return stale(v, tok) })
}

func TestOnlyTheTouchedThingsAreRefused(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	now := time.Now()
	f.add(vOrg, "", vProject, "project_state_changed", now.Add(-time.Minute))
	f.add(vOrg2, "", "", "org_state_changed", now.Add(-time.Minute))
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	old := now.Add(-10 * time.Minute)
	if !stale(v, tokenIssued(t, s, old, nil)) {
		t.Fatal("a token of the changed project is refused")
	}
	if stale(v, tokenIssued(t, s, old, map[string]any{"prj": vProject2})) {
		t.Fatal("a token of another project of the same organization is not touched")
	}
	if !stale(v, tokenIssued(t, s, old, map[string]any{"nice_org_id": vOrg2, "prj": vProject2})) {
		t.Fatal("every token of an organization that changed is refused")
	}
}

func TestTheDenySetForgetsWhatTokensHaveOutlived(t *testing.T) {
	d := newDenySet(31 * time.Minute)
	base := time.Unix(vNow, 0)
	d.mark("key-old", vOrg, 0, base.Add(-time.Hour), base)
	d.mark("key-recent", vOrg, 0, base.Add(-time.Minute), base)
	if d.size() != 1 {
		t.Fatalf("entries older than the token lifetime plus skew are dropped: %d", d.size())
	}
	if !d.stale(tokenVersion{iat: base.Add(-10 * time.Minute).Unix()}, denyKey{key: "key-recent"}) || d.stale(tokenVersion{iat: base.Unix()}, denyKey{key: "key-recent"}) {
		t.Fatal("a recent entry refuses older tokens only")
	}
}

// syncBuffer is a log sink that the feed goroutines and the test may use together.
type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return string(s.b) }

func TestARoleChangedChangeRefusesEveryOlderTokenOfThatOrganizationOnly(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	now := time.Now()
	f.add(vOrg, "", "", "role_changed", now.Add(-time.Minute))
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	old := now.Add(-10 * time.Minute)
	if !stale(v, tokenIssued(t, s, old, nil)) {
		t.Fatal("a token of the organization issued before the change is refused")
	}
	if !stale(v, tokenIssued(t, s, old, map[string]any{"prj": vProject2})) {
		t.Fatal("a token of a project of that organization is refused too: the change has no project")
	}
	if stale(v, tokenIssued(t, s, old, map[string]any{"nice_org_id": vOrg2})) {
		t.Fatal("a token of another organization is not touched")
	}
	if _, err := v.Verify(context.Background(), tokenIssued(t, s, now, nil)); err != nil {
		t.Fatalf("a token issued after the change is fine: %v", err)
	}
}

func TestTheFeedIsReadWithoutACredential(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	tok := tokenIssued(t, s, time.Now().Add(-10*time.Minute), nil)
	f.add(vOrg, vUser, "", "principal_disabled", time.Now())
	eventually(t, "the change reaches the verifier", 3*time.Second, func() bool { return stale(v, tok) })
	auths := f.authorizations()
	if len(auths) < 2 {
		t.Fatalf("the replay and at least one poll: %d requests", len(auths))
	}
	for i, a := range auths {
		if a != "" {
			t.Fatalf("request %d of the feed carries Authorization %q", i, a)
		}
	}
}

func TestAStartNeedsNoCredential(t *testing.T) {
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: staticJWKS(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := v.StartFeed(ctx, FeedConfig{BaseURL: "http://127.0.0.1:1", Wait: time.Second, MinBackoff: time.Second}); err != nil {
		t.Fatalf("a FeedConfig with an address only starts: %v", err)
	}
}

// A change names what it touched by its key and the organization it was recorded in by its org key, and refuses
// the tokens whose keys it names.
func TestAChangeRefusesTheTokensOfItsKey(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	iat := vNow - 600
	valid := claims(nil)
	actAs := claims(map[string]any{"nice_act_as": vPlatform})
	cases := []struct {
		name          string
		key, orgKey   string
		at            int64
		pv            string
		refused, kept []map[string]any
	}{
		{name: "principal in the organization", key: FeedKey("p", vUser, vOrg), orgKey: FeedKey("o", vOrg), at: iat + 1,
			refused: []map[string]any{valid, actAs}, kept: []map[string]any{claims(map[string]any{"sub": vSA}), claims(map[string]any{"nice_org_id": vOrg2})}},
		{name: "project", key: FeedKey("j", vProject), orgKey: FeedKey("o", vOrg), at: iat + 1,
			refused: []map[string]any{valid}, kept: []map[string]any{claims(map[string]any{"prj": vProject2})}},
		{name: "organization", key: FeedKey("o", vOrg), orgKey: FeedKey("o", vOrg), at: iat + 1,
			refused: []map[string]any{valid, claims(map[string]any{"sub": vSA, "prj": vProject2})}, kept: []map[string]any{claims(map[string]any{"nice_org_id": vOrg2})}},
		{name: "principal in the act-as organization", key: FeedKey("p", vUser, vPlatform), orgKey: FeedKey("o", vPlatform), at: iat,
			refused: []map[string]any{actAs}, kept: []map[string]any{valid}},
		{name: "policy version in the second of the token", key: FeedKey("p", vUser, vOrg), orgKey: FeedKey("o", vOrg), at: iat, pv: "13",
			refused: []map[string]any{valid, claims(map[string]any{"pv": 12})}, kept: []map[string]any{claims(map[string]any{"pv": 13}), claims(map[string]any{"pv": nil})}},
		{name: "policy version of another organization", key: FeedKey("p", vUser, vOrg), orgKey: FeedKey("o", vOrg2), at: iat, pv: "50",
			kept: []map[string]any{valid}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := fixedVerifier(t, s, 30*time.Minute, vectorNow, nil)
			v.feed = &feedState{}
			v.apply(feedPage{Seq: "1", Changes: []feedChange{{Seq: "1", Kind: "binding_deleted", Key: c.key, OrgKey: c.orgKey, PolicyVersion: c.pv,
				OccurredAt: time.Unix(c.at, 0).UTC().Format(time.RFC3339)}}})
			for _, cl := range c.refused {
				if _, err := v.Verify(context.Background(), s.sign(t, cl)); reason(err) != ReasonStale {
					t.Errorf("sub %v org %v prj %v act-as %v pv %v: %v, want %s", cl["sub"], cl["nice_org_id"], cl["prj"], cl["nice_act_as"], cl["pv"], err, ReasonStale)
				}
			}
			for _, cl := range c.kept {
				if _, err := v.Verify(context.Background(), s.sign(t, cl)); err != nil {
					t.Errorf("sub %v org %v prj %v act-as %v pv %v: %v, want accepted", cl["sub"], cl["nice_org_id"], cl["prj"], cl["nice_act_as"], cl["pv"], err)
				}
			}
		})
	}
}

func TestAChangeWithoutAKeyIsIgnored(t *testing.T) {
	v := fixedVerifier(t, testSigner(t, "vector-key-1"), 30*time.Minute, vectorNow, nil)
	v.feed = &feedState{}
	v.apply(feedPage{Seq: "1", Changes: []feedChange{{Seq: "1", Kind: "role_changed", OrgKey: FeedKey("o", vOrg), OccurredAt: vectorNow().UTC().Format(time.RFC3339)}}})
	if v.deny.size() != 0 || v.FeedSeq() != 1 {
		t.Fatalf("a change without a key sets nothing but moves the position: %d entries, seq %d", v.deny.size(), v.FeedSeq())
	}
}
