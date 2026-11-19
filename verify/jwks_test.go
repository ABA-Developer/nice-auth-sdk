package verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// nice is a stand-in for the JWKS endpoint of NICE.
type nice struct {
	srv  *httptest.Server
	hits atomic.Int64
	mu   sync.Mutex
	keys []jose.JSONWebKey
	down atomic.Bool
}

func newNice(t *testing.T, signers ...signer) *nice {
	n := &nice{}
	for _, s := range signers {
		n.keys = append(n.keys, jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"})
	}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.hits.Add(1)
		if n.down.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: n.keys})
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *nice) publish(s signer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.keys = append(n.keys, jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"})
}

func testSigner(t *testing.T, kid string) signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: k, kid: kid}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func verifierFor(t *testing.T, n *nice, c *clock, file string) *Verifier {
	t.Helper()
	v, err := New(Config{Issuer: vIssuer, Service: vService, JWKSURL: n.srv.URL, JWKSFile: file, Now: c.now, HTTP: n.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func newClock() *clock { return &clock{t: time.Unix(vNow, 0)} }

func TestKeysAreFetchedAtStartAndKeptOnDisk(t *testing.T) {
	s := testSigner(t, "k1")
	n := newNice(t, s)
	file := filepath.Join(t.TempDir(), "jwks.json")
	v := verifierFor(t, n, newClock(), file)
	if _, err := v.Verify(context.Background(), s.sign(t, claims(nil))); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatalf("a copy of the keys must be on disk: %v", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the copy must not be readable by others: %v", st.Mode().Perm())
	}
}

func TestARestartWhileNICEIsDownUsesTheCopyOnDisk(t *testing.T) {
	s := testSigner(t, "k1")
	n := newNice(t, s)
	file := filepath.Join(t.TempDir(), "jwks.json")
	verifierFor(t, n, newClock(), file) // first start fetches and keeps a copy
	n.down.Store(true)
	v := verifierFor(t, n, newClock(), file) // restart while NICE answers 500
	if _, err := v.Verify(context.Background(), s.sign(t, claims(nil))); err != nil {
		t.Fatalf("verification after a restart with NICE down: %v", err)
	}
}

func TestWithoutAnyKeyTheVerifierAnswers503AndRecovers(t *testing.T) {
	s := testSigner(t, "k1")
	n := newNice(t, s)
	n.down.Store(true)
	v := verifierFor(t, n, newClock(), "")
	_, err := v.Verify(context.Background(), s.sign(t, claims(nil)))
	if e, ok := err.(*Error); !ok || e.Status != http.StatusServiceUnavailable || e.Description != ReasonKeysDown {
		t.Fatalf("no key and NICE down: %v", err)
	}
	n.down.Store(false)
	if _, err := v.Verify(context.Background(), s.sign(t, claims(nil))); err != nil {
		t.Fatalf("once NICE answers the service recovers by itself: %v", err)
	}
}

func TestAnUnknownKidRefreshesAtMostOncePerMinute(t *testing.T) {
	good, stranger := testSigner(t, "k1"), testSigner(t, "random-kid")
	n := newNice(t, good)
	c := newClock()
	v := verifierFor(t, n, c, "")
	start := n.hits.Load()
	for i := 0; i < 50; i++ {
		_, err := v.Verify(context.Background(), stranger.sign(t, claims(nil)))
		if e, ok := err.(*Error); !ok || e.Status != http.StatusUnauthorized || e.Description != ReasonUnknownKey {
			t.Fatalf("unknown kid: %v", err)
		}
	}
	if got := n.hits.Load() - start; got != 1 {
		t.Fatalf("50 requests with a random kid caused %d refreshes, want 1", got)
	}
	c.add(61 * time.Second)
	_, _ = v.Verify(context.Background(), stranger.sign(t, claims(nil)))
	if got := n.hits.Load() - start; got != 2 {
		t.Fatalf("after a minute one more refresh is allowed: %d", got)
	}
}

func TestAKeyAddedByNICEIsPickedUpOnTheFirstTokenOfThatKey(t *testing.T) {
	old, rotated := testSigner(t, "k1"), testSigner(t, "k2")
	n := newNice(t, old)
	v := verifierFor(t, n, newClock(), "")
	n.publish(rotated)
	if _, err := v.Verify(context.Background(), rotated.sign(t, claims(nil))); err != nil {
		t.Fatalf("a rotated key: %v", err)
	}
	if _, err := v.Verify(context.Background(), old.sign(t, claims(nil))); err != nil {
		t.Fatalf("the old key stays valid while NICE publishes it: %v", err)
	}
}

func TestTheLastGoodKeysSurviveAFailedRefresh(t *testing.T) {
	s := testSigner(t, "k1")
	n := newNice(t, s)
	v := verifierFor(t, n, newClock(), "")
	n.down.Store(true)
	if err := v.keys.refresh(context.Background()); err == nil {
		t.Fatal("a refresh against a failing NICE must report the failure")
	}
	if _, err := v.Verify(context.Background(), s.sign(t, claims(nil))); err != nil {
		t.Fatalf("the cached keys are kept: %v", err)
	}
}

func TestConcurrentUnknownKidsShareOneRefresh(t *testing.T) {
	good, stranger := testSigner(t, "k1"), testSigner(t, "x")
	n := newNice(t, good)
	v := verifierFor(t, n, newClock(), "")
	start := n.hits.Load()
	tok := stranger.sign(t, claims(nil))
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = v.Verify(context.Background(), tok) }()
	}
	wg.Wait()
	if got := n.hits.Load() - start; got != 1 {
		t.Fatalf("concurrent requests caused %d refreshes, want 1", got)
	}
}
