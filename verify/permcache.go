package verify

import (
	"container/list"
	"slices"
	"sync"
	"time"
)

const (
	// defaultPermissionSets is how many permission lists a PermissionCache keeps when no size is given.
	defaultPermissionSets = 1024
	// staleTokensPerSet bounds the memory of stale tokens, as a multiple of the number of lists.
	staleTokensPerSet = 16
)

// PermissionCache keeps what a Verifier learned from resolving perms_ref: the permission list of each reference,
// and the tokens whose reference NICE said no longer matches. A reference is the hash of its list, so an entry
// never goes stale and tokens of every principal that hold the same permissions share one. It is safe for
// concurrent use and may be shared by several Verifiers.
type PermissionCache struct {
	mu    sync.Mutex
	max   int
	sets  map[string]*list.Element
	order *list.List // front = most recently used
	// stale maps the jti of a token NICE refused to resolve to its exp. It is per token, not per reference: the
	// same reference still names the permissions of every principal that did not change.
	stale    map[string]int64
	maxStale int
}

type permissionSet struct {
	ref         string
	permissions []string
}

// NewPermissionCache returns a cache that keeps at most maxSets permission lists and drops the least recently
// used one when it is full; maxSets below 1 means 1024.
func NewPermissionCache(maxSets int) *PermissionCache {
	if maxSets < 1 {
		maxSets = defaultPermissionSets
	}
	return &PermissionCache{max: maxSets, sets: map[string]*list.Element{}, order: list.New(),
		stale: map[string]int64{}, maxStale: maxSets * staleTokensPerSet}
}

func (pc *PermissionCache) isStale(jti string) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	_, ok := pc.stale[jti]
	return ok
}

// markStale remembers the token jti until it expires. When the memory is full it drops the tokens that have
// expired, and then the ones that expire first: forgetting one only costs another resolution.
func (pc *PermissionCache) markStale(jti string, exp, now int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if _, ok := pc.stale[jti]; !ok && len(pc.stale) >= pc.maxStale {
		for k, e := range pc.stale {
			if e+int64(maxSkew/time.Second) < now {
				delete(pc.stale, k)
			}
		}
		for len(pc.stale) >= pc.maxStale {
			first, firstExp := "", int64(0)
			for k, e := range pc.stale {
				if first == "" || e < firstExp {
					first, firstExp = k, e
				}
			}
			delete(pc.stale, first)
		}
	}
	pc.stale[jti] = exp
}

// get returns a copy of the list kept for ref, so a caller that changes it does not change the cache.
func (pc *PermissionCache) get(ref string) ([]string, bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	e, ok := pc.sets[ref]
	if !ok {
		return nil, false
	}
	pc.order.MoveToFront(e)
	return slices.Clone(e.Value.(*permissionSet).permissions), true
}

func (pc *PermissionCache) put(ref string, permissions []string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if e, ok := pc.sets[ref]; ok {
		pc.order.MoveToFront(e)
		return
	}
	pc.sets[ref] = pc.order.PushFront(&permissionSet{ref: ref, permissions: slices.Clone(permissions)})
	for pc.order.Len() > pc.max {
		oldest := pc.order.Back()
		pc.order.Remove(oldest)
		delete(pc.sets, oldest.Value.(*permissionSet).ref)
	}
}
