package verify

import (
	"container/list"
	"context"
	"errors"
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

// PermissionStore is a second place to keep permission lists, behind the memory of a PermissionCache: a store
// several replicas share, or one that outlives a restart. The cache reads it when its memory has no list for a
// reference and writes every list NICE gives. A list it returns is used only when its reference (PermsRef) is
// ref, so the store needs no more trust than a cache; an error is read as a miss.
type PermissionStore interface {
	Get(ctx context.Context, ref string) (permissions []string, ok bool, err error)
	Put(ctx context.Context, ref string, permissions []string) error
}

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
	// flights are the resolutions under way, so requests that need the same one wait for it instead of asking too.
	flights map[string]*flight
	store   PermissionStore
}

// resolution is the checked answer of a resolver: the list when match is set and err is nil.
type resolution struct {
	permissions []string
	match       bool
	err         error
}

type flight struct {
	done chan struct{}
	res  resolution
}

var errResolutionAborted = errors.New("niceauth: the permission resolution did not finish")

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
		stale: map[string]int64{}, maxStale: maxSets * staleTokensPerSet, flights: map[string]*flight{}}
}

// WithStore puts store behind the memory of the cache and returns the cache. Call it before the cache is used.
func (pc *PermissionCache) WithStore(store PermissionStore) *PermissionCache {
	pc.store = store
	return pc
}

// fromStore returns the list the store holds for ref when it is the list ref names, and keeps it in memory.
func (pc *PermissionCache) fromStore(ctx context.Context, ref string) ([]string, bool) {
	if pc.store == nil {
		return nil, false
	}
	perms, ok, err := pc.store.Get(ctx, ref)
	if err != nil || !ok || PermsRef(perms) != ref {
		return nil, false
	}
	pc.put(ref, perms)
	return perms, true
}

// keep stores a list NICE gave, in memory and in the store.
func (pc *PermissionCache) keep(ctx context.Context, ref string, permissions []string) {
	pc.put(ref, permissions)
	if pc.store != nil {
		_ = pc.store.Put(ctx, ref, permissions)
	}
}

// once runs resolve for key, or waits for the run of the same key that is under way and returns its answer. A
// caller that waits gives up when its own context ends.
func (pc *PermissionCache) once(ctx context.Context, key string, resolve func() resolution) resolution {
	pc.mu.Lock()
	if f, ok := pc.flights[key]; ok {
		pc.mu.Unlock()
		select {
		case <-f.done:
			return f.res
		case <-ctx.Done():
			return resolution{err: ctx.Err()}
		}
	}
	f := &flight{done: make(chan struct{}), res: resolution{err: errResolutionAborted}}
	pc.flights[key] = f
	pc.mu.Unlock()
	defer func() {
		pc.mu.Lock()
		delete(pc.flights, key)
		pc.mu.Unlock()
		close(f.done)
	}()
	f.res = resolve()
	return f.res
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
