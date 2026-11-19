package verify

import (
	"sort"
	"sync"
)

// Observer receives what the verifier does, so a service can expose it as
// metrics. Implementations must not block.
type Observer interface {
	// Rejected is called for every refused request with the reason (see Reason*).
	Rejected(reason string)
	// Degraded is called when the access change feed goes silent (true) and when it is back (false).
	Degraded(on bool)
	// FeedPoll is called after every read of the feed with whether it succeeded.
	FeedPoll(ok bool)
}

// Stats is an Observer that counts, for services without a metrics library.
type Stats struct {
	mu       sync.Mutex
	rejected map[string]int64
	polls    map[bool]int64
	degraded bool
	switches int64
}

// Rejected implements Observer.
func (s *Stats) Rejected(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejected == nil {
		s.rejected = map[string]int64{}
	}
	s.rejected[reason]++
}

// Degraded implements Observer.
func (s *Stats) Degraded(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.degraded = on
	s.switches++
}

// FeedPoll implements Observer.
func (s *Stats) FeedPoll(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.polls == nil {
		s.polls = map[bool]int64{}
	}
	s.polls[ok]++
}

// Snapshot returns the counters: "rejected.<reason>", "feed_polls.ok", "feed_polls.failed",
// "degraded" (1 while the feed is silent) and "degraded_switches".
func (s *Stats) Snapshot() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int64{"feed_polls.ok": s.polls[true], "feed_polls.failed": s.polls[false], "degraded_switches": s.switches}
	if s.degraded {
		out["degraded"] = 1
	} else {
		out["degraded"] = 0
	}
	for r, n := range s.rejected {
		out["rejected."+r] = n
	}
	return out
}

// Names returns the counter names in order, for stable output.
func (s *Stats) Names() []string {
	snap := s.Snapshot()
	names := make([]string, 0, len(snap))
	for n := range snap {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

type noObserver struct{}

func (noObserver) Rejected(string) {}
func (noObserver) Degraded(bool)   {}
func (noObserver) FeedPoll(bool)   {}
