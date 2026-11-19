package verify

import (
	"sync"
	"time"
)

// denySet holds "not before" times set by access changes: a token issued
// before the time of its principal, organization or project is refused.
// Entries are kept for the lifetime of a token and then dropped, because older
// tokens have expired by themselves.
type denySet struct {
	mu        sync.Mutex
	retention time.Duration
	m         map[string]int64
}

func newDenySet(retention time.Duration) *denySet {
	return &denySet{retention: retention, m: map[string]int64{}}
}

// mark refuses tokens of key issued before the second of at. A token issued
// in the same second is not caught: the resolution of iat is a second.
func (d *denySet) mark(key string, at, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if sec := at.Unix(); sec > d.m[key] {
		d.m[key] = sec
	}
	d.purgeLocked(now)
}

// stale reports whether a token issued at iat is refused for any of keys.
func (d *denySet) stale(iat int64, keys ...string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, k := range keys {
		if nb, ok := d.m[k]; ok && iat < nb {
			return true
		}
	}
	return false
}

func (d *denySet) purgeLocked(now time.Time) {
	cutoff := now.Add(-d.retention).Unix()
	for k, nb := range d.m {
		if nb < cutoff {
			delete(d.m, k)
		}
	}
}

func (d *denySet) size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.m)
}
