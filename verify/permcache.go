package verify

import (
	"container/list"
	"slices"
	"sync"
)

// defaultPermissionSets is how many permission lists a PermissionCache keeps when no size is given.
const defaultPermissionSets = 1024

// PermissionCache keeps what a Verifier learned from resolving perms_ref: the permission list of each reference.
// A reference is the hash of its list, so an entry never goes stale and tokens of every principal that hold the
// same permissions share one. It is safe for concurrent use and may be shared by several Verifiers.
type PermissionCache struct {
	mu    sync.Mutex
	max   int
	sets  map[string]*list.Element
	order *list.List // front = most recently used
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
	return &PermissionCache{max: maxSets, sets: map[string]*list.Element{}, order: list.New()}
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
