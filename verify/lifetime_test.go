package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixedVerifier(t *testing.T, s signer, ttl time.Duration, now func() time.Time, log *slog.Logger) *Verifier {
	t.Helper()
	jwks, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(s)}})
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, TokenTTL: ttl, Now: now, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Description
	}
	return ""
}

func TestATokenThatOutlivesTokenTTLIsRefused(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	now := func() time.Time { return time.Unix(vNow, 0) }
	var logs bytes.Buffer
	v := fixedVerifier(t, s, 30*time.Minute, now, slog.New(slog.NewTextHandler(&logs, nil)))
	cases := []struct {
		name string
		over map[string]any
		want string
	}{
		{"lives as long as TokenTTL", nil, ""},
		{"lives TokenTTL plus the skew", map[string]any{"exp": vNow - 600 + 1800 + 60}, ""},
		{"lives an hour", map[string]any{"exp": vNow - 600 + 3600}, ReasonLifetime},
		{"has no iat", map[string]any{"iat": nil}, ReasonLifetime},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := s.sign(t, claims(c.over))
			_, err := v.Verify(context.Background(), tok)
			if got := reason(err); got != c.want {
				t.Fatalf("reason %q, want %q (%v)", got, c.want, err)
			}
			if strings.Contains(logs.String(), tok) {
				t.Fatal("the log holds the token")
			}
		})
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("one warning a minute about the configuration, got %d:\n%s", n, logs.String())
	}
}

func TestTheLifetimeRefusalIsA401WithItsReason(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	v := fixedVerifier(t, s, 30*time.Minute, func() time.Time { return time.Unix(vNow, 0) }, nil)
	srv := httptest.NewServer(v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+s.sign(t, claims(map[string]any{"exp": vNow - 600 + 3600})))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error_description="token_lifetime_exceeded"`) {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

// A verifier whose TokenTTL is shorter than the lifetime of NICE used to forget a revocation once TokenTTL had
// passed and then accept the revoked token again, until it expired.
func TestAShortTokenTTLNeverAcceptsARevokedTokenAgain(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	var offset atomic.Int64
	start := time.Now()
	now := func() time.Time { return start.Add(time.Duration(offset.Load())) }
	v := fixedVerifier(t, s, time.Minute, now, nil)
	f := newFeedServer(t)
	startFeed(t, v, f, nil)
	tok := tokenIssued(t, s, start.Add(-2*time.Second), nil)
	if got := reason(func() error { _, err := v.Verify(context.Background(), tok); return err }()); got != ReasonLifetime {
		t.Fatalf("a token of 30 minutes under a TokenTTL of one minute: %q, want %q", got, ReasonLifetime)
	}
	f.add(vOrg, vUser, "", "binding_deleted", start)
	offset.Store(int64(3 * time.Minute))
	f.add(vOrg2, "", "", "role_changed", now()) // an unrelated change that purges the deny-set
	time.Sleep(300 * time.Millisecond)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("the revoked token is accepted again after the deny-set forgot the change")
	}
}
