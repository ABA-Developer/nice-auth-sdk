package verify

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestTheDenySetKeepsTheLatestOfEachAxis(t *testing.T) {
	d := newDenySet(31 * time.Minute)
	base := time.Unix(vNow, 0)
	d.mark("key-a", vOrg, 11, base, base)
	d.mark("key-a", vOrg, 9, base.Add(-time.Minute), base) // an older change read later keeps the newer values
	e := d.m["key-a"]
	if e.notBefore != base.Unix() || e.pv != 11 || e.org != vOrg {
		t.Fatalf("entry %+v, want the second of base, pv 11 in %s", e, vOrg)
	}
	d.mark("key-a", vOrg, 0, base.Add(time.Second), base) // a change without a version moves only the time
	if e = d.m["key-a"]; e.notBefore != base.Unix()+1 || e.pv != 11 {
		t.Fatalf("entry %+v after a change without a version", e)
	}
	d.mark("key-b", vOrg, 3, base.Add(-time.Hour), base)
	if _, ok := d.m["key-b"]; ok {
		t.Fatal("a change older than the retention is dropped, whatever its version")
	}
}

func TestStaleByPolicyVersionAndByTime(t *testing.T) {
	const s = vNow // the second of the change
	key := denyKey{key: FeedKey("p", vUser, vOrg)}
	actAs := denyKey{key: FeedKey("p", vUser, vPlatform), actAs: true}
	// The organizations are compared by their org keys, as the feed names them.
	org, org2, platform := FeedKey("o", vOrg), FeedKey("o", vOrg2), FeedKey("o", vPlatform)
	cases := []struct {
		name  string
		org   string
		pv    int64
		key   denyKey
		token tokenVersion
		stale bool
	}{
		{"same second, older pv", org, 11, key, tokenVersion{iat: s, org: org, pv: 10, hasPV: true}, true},
		{"same second, pv of the change", org, 11, key, tokenVersion{iat: s, org: org, pv: 11, hasPV: true}, false},
		{"later second, newer pv", org, 11, key, tokenVersion{iat: s + 1, org: org, pv: 12, hasPV: true}, false},
		{"earlier second, even with a newer pv", org, 11, key, tokenVersion{iat: s - 1, org: org, pv: 12, hasPV: true}, true},
		{"change of another organization", org2, 50, key, tokenVersion{iat: s, org: org, pv: 3, hasPV: true}, false},
		{"change without a version", org, 0, key, tokenVersion{iat: s, org: org, pv: 3, hasPV: true}, false},
		{"no pv, earlier second", org, 11, key, tokenVersion{iat: s - 1, org: org}, true},
		{"no pv, same second", org, 11, key, tokenVersion{iat: s, org: org}, false},
		{"act-as, same second", platform, 40, actAs, tokenVersion{iat: s, org: org, pv: 3, hasPV: true}, true},
		{"act-as, later second", platform, 40, actAs, tokenVersion{iat: s + 1, org: org, pv: 3, hasPV: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDenySet(31 * time.Minute)
			d.mark(c.key.key, c.org, c.pv, time.Unix(s, 0), time.Unix(s, 0))
			if got := d.stale(c.token, c.key); got != c.stale {
				t.Fatalf("stale = %v, want %v", got, c.stale)
			}
		})
	}
}

func TestVerifyReadsWhetherTheTokenCarriesPV(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	v := fixedVerifier(t, s, 30*time.Minute, func() time.Time { return time.Unix(vNow, 0) }, nil)
	iat := vNow - 600
	v.deny.mark(FeedKey("p", vUser, vOrg), FeedKey("o", vOrg), 13, time.Unix(iat, 0), time.Unix(vNow, 0))
	verify := func(over map[string]any) string {
		_, err := v.Verify(context.Background(), s.sign(t, claims(over)))
		return reason(err)
	}
	if got := verify(map[string]any{"pv": 12}); got != ReasonStale {
		t.Fatalf("a token of the second of the change with an older pv: %q, want %q", got, ReasonStale)
	}
	if got := verify(map[string]any{"pv": 13}); got != "" {
		t.Fatalf("a token with the pv of the change: %q", got)
	}
	if got := verify(map[string]any{"pv": nil}); got != "" {
		t.Fatalf("a token without pv of the same second is judged by time only: %q", got)
	}
	if got := verify(map[string]any{"pv": 0}); got != ReasonStale {
		t.Fatalf("pv 0 is a version, older than 13: %q", got)
	}
}

func TestTheFeedRefusesATokenOfTheSecondOfTheChange(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	v := liveVerifier(t, s, nil)
	startFeed(t, v, f, nil)
	issued := time.Now().Truncate(time.Second)
	before := tokenIssued(t, s, issued, map[string]any{"pv": 41})
	after := tokenIssued(t, s, issued, map[string]any{"pv": 42})
	f.addVersion(vOrg, vUser, "", "binding_deleted", issued.Add(400*time.Millisecond), 42)
	eventually(t, "the change to reach the verifier", 3*time.Second, func() bool { return stale(v, before) })
	if _, err := v.Verify(context.Background(), after); err != nil {
		t.Fatalf("a token issued after the change in the same second is fine: %v", err)
	}
}

func (f *feedServer) addVersion(org, principal, project, kind string, at time.Time, pv int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, orgKey := changeKeys(org, principal, project)
	f.changes = append(f.changes, feedChange{Seq: strconv.Itoa(len(f.changes) + 1), Key: key, OrgKey: orgKey, Kind: kind,
		PolicyVersion: strconv.FormatInt(pv, 10), OccurredAt: at.UTC().Format(time.RFC3339Nano)})
}
