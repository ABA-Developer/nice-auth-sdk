package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store keeps what must outlive a process or be shared by several: the refresh
// token of each subject and the latest access tokens. The application owns it,
// so it can encrypt the values or keep them in its own database.
//
// Access tokens are kept per whole Key, Org included: a Store of your own must
// tell keys that differ only in Org apart, or a token of one organization is
// handed out for another.
type Store interface {
	// RefreshToken returns the refresh token of subject, or ErrNotConnected.
	RefreshToken(ctx context.Context, subject string) (string, error)
	// SaveRefreshToken replaces the refresh token of subject.
	SaveRefreshToken(ctx context.Context, subject, token string) error
	// DeleteSubject forgets everything of subject.
	DeleteSubject(ctx context.Context, subject string) error
	// LoadToken returns the access token last saved for key, if any.
	LoadToken(ctx context.Context, key Key) (Token, bool, error)
	// SaveToken keeps the access token fetched for key. A zero Token forgets the token of key; a Store
	// may keep it instead, since a token that has expired is never handed out.
	SaveToken(ctx context.Context, key Key, t Token) error
	// Lock holds the right to use the refresh token of subject, across processes
	// that share the store. The refresh token rotates, so two uses at once would
	// look like a replay and end the session.
	Lock(ctx context.Context, subject string) (unlock func(), err error)
}

// MemoryStore is a Store in memory, for one process.
type MemoryStore struct {
	mu      sync.Mutex
	refresh map[string]string
	tokens  map[Key]Token
	locks   map[string]*sync.Mutex
	pend    memoryPending
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{refresh: map[string]string{}, tokens: map[Key]Token{}, locks: map[string]*sync.Mutex{}}
}

func (m *MemoryStore) RefreshToken(_ context.Context, subject string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.refresh[subject]; ok {
		return t, nil
	}
	return "", ErrNotConnected
}

func (m *MemoryStore) SaveRefreshToken(_ context.Context, subject, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[subject] = token
	return nil
}

func (m *MemoryStore) DeleteSubject(_ context.Context, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refresh, subject)
	for k := range m.tokens {
		if k.Subject == subject {
			delete(m.tokens, k)
		}
	}
	return nil
}

func (m *MemoryStore) LoadToken(_ context.Context, key Key) (Token, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[key]
	return t, ok, nil
}

func (m *MemoryStore) SaveToken(_ context.Context, key Key, t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t == (Token{}) {
		delete(m.tokens, key)
		return nil
	}
	m.tokens[key] = t
	return nil
}

func (m *MemoryStore) Lock(_ context.Context, subject string) (func(), error) {
	m.mu.Lock()
	l, ok := m.locks[subject]
	if !ok {
		l = &sync.Mutex{}
		m.locks[subject] = l
	}
	m.mu.Unlock()
	l.Lock()
	return l.Unlock, nil
}

// FileStore is a Store in a directory, shared by the processes of one machine
// that act for the same subjects. Files are readable by the owner only. The lock
// is a file created exclusively; one left by a process that died is broken after
// StaleLock. Refresh tokens are secrets: keep the directory on an encrypted disk
// or use a Store of your own that encrypts them.
type FileStore struct {
	dir string
	// StaleLock is how long a lock may be held before it is taken over; default 30 seconds.
	StaleLock time.Duration
	// LockWait is how long Lock waits for the lock; default 30 seconds.
	LockWait time.Duration
}

// NewFileStore uses dir, which is created when it does not exist.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir, StaleLock: 30 * time.Second, LockWait: 30 * time.Second}, nil
}

func (f *FileStore) path(kind, name string) string {
	return filepath.Join(f.dir, kind+"-"+safe(name))
}

// safe turns a subject or key into a file name that cannot leave the directory.
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "~%x", r)
		}
	}
	return b.String()
}

func (f *FileStore) write(path string, data []byte) error {
	tmp, err := os.CreateTemp(f.dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Close()
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (f *FileStore) RefreshToken(_ context.Context, subject string) (string, error) {
	b, err := os.ReadFile(f.path("refresh", subject))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotConnected
	}
	return string(b), err
}

func (f *FileStore) SaveRefreshToken(_ context.Context, subject, token string) error {
	return f.write(f.path("refresh", subject), []byte(token))
}

func (f *FileStore) DeleteSubject(_ context.Context, subject string) error {
	_ = os.Remove(f.path("refresh", subject))
	matches, _ := filepath.Glob(f.path("token", subject) + "+*")
	for _, m := range matches {
		_ = os.Remove(m)
	}
	return nil
}

// tokenPath names the file of key. The organization is the last part, only when set, so the files
// written before keys had one are still read for a key without it.
func (f *FileStore) tokenPath(key Key) string {
	p := f.path("token", key.Subject) + "+" + safe(key.Audience) + "+" + safe(key.Project)
	if key.Org != "" {
		p += "+" + safe(key.Org)
	}
	return p
}

func (f *FileStore) LoadToken(_ context.Context, key Key) (Token, bool, error) {
	b, err := os.ReadFile(f.tokenPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, err
	}
	var t Token
	if json.Unmarshal(b, &t) != nil {
		return Token{}, false, nil
	}
	return t, true, nil
}

func (f *FileStore) SaveToken(_ context.Context, key Key, t Token) error {
	if t == (Token{}) {
		if err := os.Remove(f.tokenPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, _ := json.Marshal(t)
	return f.write(f.tokenPath(key), b)
}

func (f *FileStore) Lock(ctx context.Context, subject string) (func(), error) {
	path := f.path("lock", subject)
	deadline := time.Now().Add(f.LockWait)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > f.StaleLock {
			_ = os.Remove(path) // the holder died
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("niceauth: waited too long for the refresh token lock of " + subject)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
