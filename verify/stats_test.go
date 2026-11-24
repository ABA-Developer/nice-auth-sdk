package verify

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRejectionsAreCountedByReasonAndNeverLogTheToken(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	stats := &Stats{}
	var logs bytes.Buffer
	jwks := mustJSON(map[string]any{"keys": []any{publicJWK(s)}})
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Observer: stats, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	h := v.Middleware(v.Require("navi.orders.read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	send := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	now := time.Now()
	good := tokenIssued(t, s, now.Add(-time.Minute), nil)
	_ = send(good)
	_ = send("")
	_ = send("garbage")
	_ = send(tokenIssued(t, s, now.Add(-time.Hour), nil))                                                       // expired
	_ = send(tokenIssued(t, s, now.Add(-time.Minute), map[string]any{"perms": []string{"navi.orders.delete"}})) // lacks the permission
	snap := stats.Snapshot()
	for reason, want := range map[string]int64{"missing_token": 1, ReasonMalformed: 1, ReasonExpired: 1, ReasonPermission: 1} {
		if snap["rejected."+reason] != want {
			t.Errorf("rejected.%s = %d, want %d (%v)", reason, snap["rejected."+reason], want, snap)
		}
	}
	if strings.Contains(logs.String(), good) {
		t.Fatal("the log must never carry a token")
	}
	if names := stats.Names(); len(names) == 0 || names[0] > names[len(names)-1] {
		t.Fatalf("names are sorted for stable output: %v", names)
	}
}

func TestEnteringAndLeavingDegradedModeIsLogged(t *testing.T) {
	s := testSigner(t, "vector-key-1")
	f := newFeedServer(t)
	var logs syncBuffer
	jwks := mustJSON(map[string]any{"keys": []any{publicJWK(s)}})
	stats := &Stats{}
	v, err := New(Config{Issuer: vIssuer, Service: vService, StaticJWKS: jwks, Observer: stats, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	startFeed(t, v, f, nil)
	eventually(t, "the feed answers", 2*time.Second, func() bool { return !v.Degraded() && stats.Snapshot()["feed_polls.ok"] > 0 })
	f.setDown(true)
	eventually(t, "degraded mode is entered", 3*time.Second, func() bool { return v.Degraded() })
	f.setDown(false)
	eventually(t, "degraded mode is left", 5*time.Second, func() bool { return !v.Degraded() })
	eventually(t, "leaving degraded mode is logged", 2*time.Second, func() bool {
		return strings.Contains(logs.String(), "the access change feed is back")
	})
	out := logs.String()
	for _, want := range []string{"the access change feed is silent", "the access change feed is back", "reading the access change feed failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "reader-key") {
		t.Fatal("the log must never carry the API key")
	}
}
