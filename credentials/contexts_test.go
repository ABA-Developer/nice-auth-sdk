package credentials

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeContexts plays NICE for Contexts: the token exchange at /oauth/token and GET /api/v1/me/contexts, answered by
// page until it is set.
type fakeContexts struct {
	*fakeExchange
	srv *httptest.Server

	mu      sync.Mutex
	queries []url.Values
	bearers []string
	// page answers the call with index n (from 0).
	page func(w http.ResponseWriter, r *http.Request, n int)
}

func newFakeContexts(t *testing.T) (*fakeContexts, *ExchangeClient, string) {
	t.Helper()
	clk := newClock()
	f := &fakeContexts{fakeExchange: &fakeExchange{clk: clk}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			f.serve(w, r)
		case "/api/v1/me/contexts":
			f.mu.Lock()
			n := len(f.queries)
			f.queries = append(f.queries, r.URL.Query())
			f.bearers = append(f.bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			page := f.page
			f.mu.Unlock()
			page(w, r, n)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	x, err := NewExchange(ExchangeConfig{Issuer: f.srv.URL, ClientID: "naia-web", ClientSecret: "s3cret", Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return f, x, subject(clk, "usr_1", "org_a", "", 30*time.Minute)
}

func (f *fakeContexts) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.queries) }

// secrets are every string that must stay out of an error: the subject token, the delegated tokens and the secret.
func (f *fakeContexts) secrets(sub string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{sub, "s3cret"}
	for _, b := range f.bearers {
		if b != "" {
			out = append(out, b)
		}
	}
	return out
}

func orgJSON(id string, projects ...string) map[string]any {
	ps := []map[string]any{}
	for _, p := range projects {
		ps = append(ps, map[string]any{"id": p, "name": "Project " + p, "slug": p, "services": []string{"navi"}})
	}
	return map[string]any{"id": id, "name": "Org " + id, "slug": id, "projects": ps, "projects_truncated": false, "act_as": false,
		"appearance": map[string]any{"logo_url": "https://cdn.example/logo.png"}}
}

func TestContextsOnePage(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"current_organization_id": "org_a", "services": []string{"navi"},
			"organizations": []any{orgJSON("org_a", "prj_p")}, "page": map[string]any{"next_page_token": ""}, "unknown": 1})
	}
	got, err := x.Contexts(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	want := Contexts{CurrentOrganization: "org_a", Services: []string{"navi"}, Organizations: []ContextOrganization{{
		ID: "org_a", Name: "Org org_a", Slug: "org_a",
		Projects: []ContextProject{{ID: "prj_p", Name: "Project prj_p", Slug: "prj_p", Services: []string{"navi"}}},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if f.count() != 1 || f.forms[0].Get("scope") != "nice:aud:nice" || f.forms[0].Get("subject_token") != sub {
		t.Fatalf("one exchange for the NICE API: %d %v", f.count(), f.forms)
	}
	if f.calls() != 1 || f.queries[0].Get("page_size") != "50" || f.queries[0].Has("page_token") {
		t.Fatalf("one call with page_size 50: %v", f.queries)
	}
	if f.bearers[0] == sub || !strings.HasPrefix(f.bearers[0], "h.") {
		t.Fatalf("the call carries the delegated token, not the subject token: %q", f.bearers[0])
	}
}

func TestContextsReadsEveryPageInOrder(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		next := ""
		if n < 2 {
			next = fmt.Sprintf("tok-%d", n+1)
		}
		writeJSON(w, http.StatusOK, map[string]any{"current_organization_id": "org_0", "services": []string{"navi"},
			"organizations": []any{orgJSON(fmt.Sprintf("org_%d", 2*n)), orgJSON(fmt.Sprintf("org_%d", 2*n+1))},
			"page":          map[string]any{"next_page_token": next}})
	}
	got, err := x.Contexts(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, o := range got.Organizations {
		ids = append(ids, o.ID)
	}
	if strings.Join(ids, ",") != "org_0,org_1,org_2,org_3,org_4,org_5" {
		t.Fatalf("organizations %v", ids)
	}
	if f.calls() != 3 || f.queries[1].Get("page_token") != "tok-1" || f.queries[2].Get("page_token") != "tok-2" {
		t.Fatalf("the next page token is followed: %v", f.queries)
	}
	if f.count() != 1 {
		t.Fatalf("one exchange for all pages, got %d", f.count())
	}
}

func TestContextsCarriesActAsAndTruncation(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		operated := orgJSON("org_op")
		operated["act_as"] = true
		big := orgJSON("org_big", "prj_1")
		big["projects_truncated"] = true
		writeJSON(w, http.StatusOK, map[string]any{"current_organization_id": "org_big", "organizations": []any{big, operated}})
	}
	got, err := x.Contexts(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	o := got.Organizations
	if len(o) != 2 || o[0].ActAs || !o[0].ProjectsTruncated || !o[1].ActAs || o[1].ProjectsTruncated {
		t.Fatalf("organizations %+v", o)
	}
}

func TestContextsExchangesOnceForOneSubjectToken(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{orgJSON("org_a")}})
	}
	for i := 0; i < 2; i++ {
		if _, err := x.Contexts(context.Background(), sub); err != nil {
			t.Fatal(err)
		}
	}
	if f.count() != 1 || f.calls() != 2 {
		t.Fatalf("%d exchanges and %d calls, want 1 and 2", f.count(), f.calls())
	}
}

func TestContextsExchangesAgainOnceOnAStaleToken(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "error_code": "token_stale", "message": "stale"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{orgJSON("org_a")}})
	}
	got, err := x.Contexts(context.Background(), sub)
	if err != nil || len(got.Organizations) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if f.count() != 2 || f.calls() != 2 || f.bearers[0] == f.bearers[1] {
		t.Fatalf("one more exchange and one more call with the new token: %d exchanges, %d calls", f.count(), f.calls())
	}

	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "error_code": "token_stale", "message": "stale"})
	}
	_, err = x.Contexts(context.Background(), sub)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized || f.calls() != 4 {
		t.Fatalf("a second stale answer is returned: %v, %d calls", err, f.calls())
	}
}

func TestContextsStopsAfterTheLastAllowedPage(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{orgJSON(fmt.Sprintf("org_%d", n))},
			"page": map[string]any{"next_page_token": fmt.Sprintf("tok-%d", n+1)}})
	}
	got, err := x.Contexts(context.Background(), sub)
	if err == nil || !reflect.DeepEqual(got, Contexts{}) || f.calls() != maxContextsPages {
		t.Fatalf("an error and no contexts after %d pages: %+v %v, %d calls", maxContextsPages, got, err, f.calls())
	}
}

func TestContextsRefusesAPageLargerThanTheBound(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{orgJSON("org_a")}, "page": map[string]any{"next_page_token": "tok-1"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{orgJSON("org_b")}, "padding": strings.Repeat("x", maxContextsBody)})
	}
	got, err := x.Contexts(context.Background(), sub)
	if err == nil || !reflect.DeepEqual(got, Contexts{}) || IsTemporary(err) {
		t.Fatalf("a body over the bound is an error and no contexts: %+v %v", got, err)
	}
}

func TestContextsErrors(t *testing.T) {
	for _, c := range []struct {
		name      string
		page      func(w http.ResponseWriter, r *http.Request, n int)
		status    int
		code      string
		temporary bool
	}{
		{"user_required", func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "error_code": "user_required", "message": "a user token is required",
				"errors": []any{}, "request_id": "req_1"})
		}, http.StatusForbidden, "user_required", false},
		{"unavailable", func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": 503, "error_code": "unavailable", "message": "try later"})
		}, http.StatusServiceUnavailable, "unavailable", true},
		{"rate limited", func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"code": 429, "error_code": "rate_limited"})
		}, http.StatusTooManyRequests, "rate_limited", true},
		{"not json", func(w http.ResponseWriter, r *http.Request, n int) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "<html>raw proxy page "+r.Header.Get("Authorization")+"</html>")
		}, http.StatusNotFound, "", false},
		{"second page fails", func(w http.ResponseWriter, r *http.Request, n int) {
			if n == 0 {
				writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{orgJSON("org_a")}, "page": map[string]any{"next_page_token": "tok-1"}})
				return
			}
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": 502, "error_code": "upstream"})
		}, http.StatusBadGateway, "upstream", true},
		{"redirect", func(w http.ResponseWriter, r *http.Request, n int) {
			http.Redirect(w, r, "https://elsewhere.example/api/v1/me/contexts", http.StatusFound)
		}, http.StatusFound, "redirect", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, x, sub := newFakeContexts(t)
			f.page = c.page
			got, err := x.Contexts(context.Background(), sub)
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != c.status || ae.Code != c.code || IsTemporary(err) != c.temporary {
				t.Fatalf("got %#v (temporary %v)", err, IsTemporary(err))
			}
			if !reflect.DeepEqual(got, Contexts{}) {
				t.Fatalf("no contexts on an error: %+v", got)
			}
			if errors.Is(err, ErrSessionEnded) {
				t.Fatal("an answer of the API does not end the session")
			}
			if c.name == "user_required" && (ae.Message != "a user token is required" || ae.RequestID != "req_1") {
				t.Fatalf("message and request ID: %+v", ae)
			}
			if strings.Contains(err.Error(), "raw proxy page") {
				t.Fatalf("the raw body is in the error: %v", err)
			}
			for _, s := range f.secrets(sub) {
				if strings.Contains(err.Error(), s) {
					t.Fatalf("a secret is in the error: %v", err)
				}
			}
		})
	}
}

func TestContextsReportsANiceThatDoesNotAnswerAsTemporary(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.page = func(w http.ResponseWriter, r *http.Request, n int) { panic(http.ErrAbortHandler) }
	got, err := x.Contexts(context.Background(), sub)
	if !IsTemporary(err) || !reflect.DeepEqual(got, Contexts{}) {
		t.Fatalf("a dropped connection is temporary: %v", err)
	}
	for _, s := range f.secrets(sub) {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("a secret is in the error: %v", err)
		}
	}
}

func TestContextsReturnsTheRefusalOfTheExchange(t *testing.T) {
	f, x, sub := newFakeContexts(t)
	f.refuse = "invalid_grant"
	f.page = func(w http.ResponseWriter, r *http.Request, n int) { t.Error("NICE API called without a token") }
	_, err := x.Contexts(context.Background(), sub)
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "invalid_grant" || f.calls() != 0 {
		t.Fatalf("the GrantError of the exchange: %v", err)
	}
	if strings.Contains(err.Error(), sub) || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("a secret is in the error: %v", err)
	}
}
