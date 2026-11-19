package verify

import (
	"sync"
	"time"
)

// denySet holds what access changes set on a key (the principal in an organization, the organization, or the
// project): the second of the latest change, and the highest policy version of the organization it was recorded in.
// A token issued before is refused. Entries are kept for the lifetime of a token and then dropped, because older
// tokens have expired by themselves.
type denySet struct {
	mu        sync.Mutex
	retention time.Duration
	m         map[string]denyEntry
}

type denyEntry struct {
	// notBefore is the unix second of the latest change.
	notBefore int64
	// org is the organization the changes were recorded in, and pv the highest policy version they carried there.
	org string
	pv  int64
}

// denyKey is a key a token is checked against. actAs marks the principal in the organization nice_act_as names:
// its changes are in another organization than the token, so only their time can be compared.
type denyKey struct {
	key   string
	actAs bool
}

// tokenVersion is what a token says of when it was issued: iat, its organization, and pv when it has one.
type tokenVersion struct {
	iat   int64
	org   string
	pv    int64
	hasPV bool
}

func newDenySet(retention time.Duration) *denySet {
	return &denySet{retention: retention, m: map[string]denyEntry{}}
}

// mark records a change of key, recorded at at in org with policy version pv (0 when the feed gives none).
func (d *denySet) mark(key, org string, pv int64, at, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.m[key]
	if sec := at.Unix(); sec > e.notBefore {
		e.notBefore = sec
	}
	if pv > e.pv {
		e.pv, e.org = pv, org
	}
	d.m[key] = e
	d.purgeLocked(now)
}

// stale reports whether a token is refused for any of keys. A token with pv is refused when an organization it
// belongs to recorded a change of a higher version, whatever the second: two events of one second keep their order.
// The second of iat is compared too, for tokens without pv and for the act-as key; there a token of the same second
// as the change is refused, since NICE issues no act-as token once the operator role is gone.
func (d *denySet) stale(t tokenVersion, keys ...denyKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, k := range keys {
		e, ok := d.m[k.key]
		if !ok {
			continue
		}
		if t.iat < e.notBefore || k.actAs && t.iat <= e.notBefore {
			return true
		}
		if !k.actAs && t.hasPV && e.pv > 0 && e.org == t.org && t.pv < e.pv {
			return true
		}
	}
	return false
}

func (d *denySet) purgeLocked(now time.Time) {
	cutoff := now.Add(-d.retention).Unix()
	for k, e := range d.m {
		if e.notBefore < cutoff {
			delete(d.m, k)
		}
	}
}

func (d *denySet) size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.m)
}
