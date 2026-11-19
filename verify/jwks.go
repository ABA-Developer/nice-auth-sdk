package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// keySet caches the public keys of NICE by kid. It keeps the last good set when
// NICE cannot be reached and a copy on disk for a service that restarts then.
type keySet struct {
	url, file string
	client    *http.Client
	log       *slog.Logger
	now       func() time.Time
	// minUnknown is the least time between refreshes caused by an unknown kid.
	minUnknown time.Duration
	static     bool

	mu          sync.RWMutex
	keys        map[string]any
	lastUnknown time.Time
	refreshMu   sync.Mutex
}

func (k *keySet) load(set jose.JSONWebKeySet) {
	m := make(map[string]any, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyID == "" || !key.Valid() || !key.IsPublic() {
			continue
		}
		m[key.KeyID] = key.Key
	}
	if len(m) == 0 {
		return
	}
	k.mu.Lock()
	k.keys = m
	k.mu.Unlock()
}

func (k *keySet) lookup(kid string) (any, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[kid]
	return key, ok
}

func (k *keySet) empty() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.keys) == 0
}

// readFile loads the copy on disk, if there is one.
func (k *keySet) readFile() {
	if k.file == "" {
		return
	}
	b, err := os.ReadFile(k.file)
	if err != nil {
		return
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal(b, &set) == nil {
		k.load(set)
	}
}

// writeFile keeps the set on disk atomically.
func (k *keySet) writeFile(raw []byte) {
	if k.file == "" {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(k.file), ".jwks-*")
	if err != nil {
		k.log.Warn("niceauth: cannot keep a copy of the JWKS", slog.String("error", err.Error()))
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Close()
	}
	if err == nil {
		err = os.Rename(tmp.Name(), k.file)
	}
	if err != nil {
		k.log.Warn("niceauth: cannot keep a copy of the JWKS", slog.String("error", err.Error()))
	}
}

// refresh fetches the JWKS. A failure leaves the cached set as it is.
func (k *keySet) refresh(ctx context.Context) error {
	if k.static {
		return nil
	}
	k.refreshMu.Lock()
	defer k.refreshMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: %s answered %d", k.url, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return err
	}
	before := k.size()
	k.load(set)
	if k.size() == 0 || (before == 0 && k.size() == 0) {
		return errors.New("jwks: no usable key")
	}
	k.writeFile(raw)
	return nil
}

func (k *keySet) size() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.keys)
}

// unknown is called for a kid that is not cached. It refreshes at most once per
// minUnknown, so random kids cannot turn the service into a load on NICE, and
// concurrent requests share the one refresh.
func (k *keySet) unknown(ctx context.Context, kid string) (any, bool) {
	k.mu.Lock()
	due := k.now().Sub(k.lastUnknown) >= k.minUnknown
	if due {
		k.lastUnknown = k.now()
	}
	k.mu.Unlock()
	if due {
		if err := k.refresh(ctx); err != nil {
			k.log.Warn("niceauth: JWKS refresh failed", slog.String("error", err.Error()))
		}
	}
	return k.lookup(kid)
}
