package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// FeedConfig configures the reader of the access change feed of NICE.
type FeedConfig struct {
	// BaseURL is the public address of NICE; default the issuer.
	BaseURL string
	// APIKey is the key of the Service Account that holds the nice.service role.
	// It is left out of the JSON form, so a FeedConfig inside a logged struct does not show it.
	APIKey string `json:"-"`
	// Wait is how long NICE holds a read when there is no change, 0 to 30 seconds; default 25.
	Wait time.Duration
	// Replay is how far back a start reads; default the token lifetime plus skew.
	Replay time.Duration
	// HTTP defaults to a client that waits longer than Wait. The feed is read through a copy that follows no redirect.
	HTTP *http.Client
	// MonitorEvery is how often silence of the feed is checked; default one second.
	MonitorEvery time.Duration
	// SilentAfter is how long without a sign of life makes the feed degraded; default two waits plus two seconds.
	SilentAfter time.Duration
	// MinBackoff and MaxBackoff bound the wait after a failed read; default 1 and 30 seconds.
	MinBackoff, MaxBackoff time.Duration
}

// String shows the FeedConfig without the API key; %v, %+v and %#v print it.
func (fc FeedConfig) String() string {
	return fmt.Sprintf("verify.FeedConfig{BaseURL:%q Wait:%s APIKey:%s}", fc.BaseURL, fc.Wait, redacted(fc.APIKey))
}

// GoString is String.
func (fc FeedConfig) GoString() string { return fc.String() }

// LogValue keeps the API key out of structured logs.
func (fc FeedConfig) LogValue() slog.Value {
	return slog.GroupValue(slog.String("base_url", fc.BaseURL), slog.Duration("wait", fc.Wait), slog.String("api_key", redacted(fc.APIKey)))
}

type feedState struct {
	lastOK   atomic.Int64 // unix nanoseconds of the last successful read
	degraded atomic.Bool
	started  atomic.Bool
	seq      atomic.Int64
	wait     time.Duration
}

// Degraded reports whether the feed has been silent for more than two waits. The
// service then still answers ordinary operations, bounded by the lifetime of
// the token, and sensitive operations keep checking online.
func (v *Verifier) Degraded() bool { return v.feed != nil && v.feed.degraded.Load() }

// FeedSeq is the position the feed has reached.
func (v *Verifier) FeedSeq() int64 {
	if v.feed == nil {
		return 0
	}
	return v.feed.seq.Load()
}

type feedChange struct {
	Seq            string `json:"seq"`
	OrganizationID string `json:"organization_id"`
	Kind           string `json:"kind"`
	PrincipalID    string `json:"principal_id"`
	ProjectID      string `json:"project_id"`
	PolicyVersion  string `json:"policy_version"`
	OccurredAt     string `json:"occurred_at"`
}

type feedPage struct {
	Changes []feedChange `json:"changes"`
	Seq     string       `json:"seq"`
}

// StartFeed replays the last token lifetime of access changes, so a service that
// restarts does not accept tokens revoked while it was down, and then keeps
// reading the feed in the background until ctx is done. A replay that fails does
// not stop the start: the service runs degraded until the feed answers.
func (v *Verifier) StartFeed(ctx context.Context, fc FeedConfig) error {
	if fc.APIKey == "" {
		return errConfig("FeedConfig.APIKey is required")
	}
	if fc.BaseURL == "" {
		fc.BaseURL = v.cfg.Issuer
	}
	fc.BaseURL = strings.TrimRight(fc.BaseURL, "/")
	if err := checkURL("FeedConfig.BaseURL", fc.BaseURL, v.cfg.AllowInsecureHTTP); err != nil {
		return err
	}
	if fc.Wait <= 0 || fc.Wait > 30*time.Second {
		fc.Wait = 25 * time.Second
	}
	if fc.Replay <= 0 {
		fc.Replay = v.cfg.TokenTTL + v.cfg.Skew
	}
	if fc.HTTP == nil {
		fc.HTTP = &http.Client{Timeout: fc.Wait + 15*time.Second}
	}
	fc.HTTP = noRedirect(fc.HTTP)
	if fc.MonitorEvery <= 0 {
		fc.MonitorEvery = time.Second
	}
	if fc.MinBackoff <= 0 {
		fc.MinBackoff = time.Second
	}
	if fc.MaxBackoff <= 0 {
		fc.MaxBackoff = 30 * time.Second
	}
	st := &feedState{wait: fc.Wait}
	if !st.started.CompareAndSwap(false, true) {
		return nil
	}
	v.feed = st
	replayed := true
	if err := v.replay(ctx, fc); err != nil {
		replayed = false
		v.cfg.Log.Warn("niceauth: the replay of access changes failed; running degraded until the feed answers", slog.String("error", err.Error()))
	}
	go v.readFeed(ctx, fc, replayed)
	go v.monitorFeed(ctx, fc)
	return nil
}

// replay reads every change of the last Replay, page by page.
func (v *Verifier) replay(ctx context.Context, fc FeedConfig) error {
	q := url.Values{"since": {v.cfg.Now().Add(-fc.Replay).UTC().Format(time.RFC3339)}, "limit": {"1000"}}
	for {
		page, err := v.fetchFeed(ctx, fc, q)
		if err != nil {
			return err
		}
		v.apply(page)
		if len(page.Changes) < 1000 {
			return nil
		}
		q = url.Values{"after_seq": {page.Seq}, "limit": {"1000"}}
	}
}

func (v *Verifier) readFeed(ctx context.Context, fc FeedConfig, replayed bool) {
	backoff := fc.MinBackoff
	for ctx.Err() == nil {
		var page feedPage
		var err error
		if replayed {
			// The position is always known after a replay, so a quiet start (position 0) loses no first change.
			q := url.Values{"after_seq": {strconv.FormatInt(v.feed.seq.Load(), 10)}, "wait_seconds": {strconv.Itoa(int(fc.Wait / time.Second))}}
			page, err = v.fetchFeed(ctx, fc, q)
		} else if err = v.replay(ctx, fc); err == nil {
			replayed = true
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			v.obs.FeedPoll(false)
			v.cfg.Log.Warn("niceauth: reading the access change feed failed", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, fc.MaxBackoff)
			continue
		}
		backoff = fc.MinBackoff
		v.apply(page)
	}
}

func (v *Verifier) fetchFeed(ctx context.Context, fc FeedConfig, q url.Values) (feedPage, error) {
	var page feedPage
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fc.BaseURL+"/api/v1/access-changes?"+q.Encode(), nil)
	if err != nil {
		return page, err
	}
	req.Header.Set("Authorization", "ApiKey "+fc.APIKey)
	resp, err := fc.HTTP.Do(req)
	if err != nil {
		return page, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return page, fmt.Errorf("feed answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&page); err != nil {
		return page, err
	}
	return page, nil
}

// apply records a page: every change refuses the tokens of what it touched that
// were issued before it. A page also counts as a sign of life of the feed.
func (v *Verifier) apply(p feedPage) {
	now := v.cfg.Now()
	for _, c := range p.Changes {
		at, err := time.Parse(time.RFC3339Nano, c.OccurredAt)
		if err != nil {
			at = now
		}
		// A version that does not parse (an older NICE sends none) leaves only the time to compare.
		pv, _ := strconv.ParseInt(c.PolicyVersion, 10, 64)
		switch {
		case c.PrincipalID != "":
			v.deny.mark("p:"+c.PrincipalID+"|"+c.OrganizationID, c.OrganizationID, pv, at, now)
		case c.ProjectID != "":
			v.deny.mark("j:"+c.ProjectID, c.OrganizationID, pv, at, now)
		default:
			v.deny.mark("o:"+c.OrganizationID, c.OrganizationID, pv, at, now)
		}
	}
	if seq, err := strconv.ParseInt(p.Seq, 10, 64); err == nil && seq > v.feed.seq.Load() {
		v.feed.seq.Store(seq)
	}
	v.feed.lastOK.Store(now.UnixNano())
	v.obs.FeedPoll(true)
}

// monitorFeed marks the feed degraded when it has been silent for more than two
// waits (a quiet feed still answers with a heartbeat at every wait).
func (v *Verifier) monitorFeed(ctx context.Context, fc FeedConfig) {
	t := time.NewTicker(fc.MonitorEvery)
	defer t.Stop()
	limit := fc.SilentAfter
	if limit <= 0 {
		limit = 2*fc.Wait + 2*time.Second
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			last := v.feed.lastOK.Load()
			silent := last == 0 || v.cfg.Now().Sub(time.Unix(0, last)) > limit
			if v.feed.degraded.Swap(silent) != silent {
				v.obs.Degraded(silent)
				if silent {
					v.cfg.Log.Warn("niceauth: the access change feed is silent; running degraded, bounded by the token lifetime", slog.Duration("silent_for", limit))
				} else {
					v.cfg.Log.Info("niceauth: the access change feed is back")
				}
			}
		}
	}
}
