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

// fakeAPI plays NICE for the service map and the operations of a service: the token exchange at /oauth/token and
// every path under /api/v1/me/, answered by answer.
type fakeAPI struct {
	*fakeExchange
	srv *httptest.Server

	mu      sync.Mutex
	uris    []string // the request targets as sent, still escaped
	queries []url.Values
	bearers []string
	// answer serves the call with index n (from 0).
	answer func(w http.ResponseWriter, r *http.Request, n int)
}

func newFakeAPI(t *testing.T) (*fakeAPI, *ExchangeClient, string) {
	t.Helper()
	clk := newClock()
	f := &fakeAPI{fakeExchange: &fakeExchange{clk: clk}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			f.serve(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/me/"):
			f.mu.Lock()
			n := len(f.uris)
			f.uris = append(f.uris, r.RequestURI)
			f.queries = append(f.queries, r.URL.Query())
			f.bearers = append(f.bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			answer := f.answer
			f.mu.Unlock()
			answer(w, r, n)
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

func (f *fakeAPI) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.uris) }

func (f *fakeAPI) uri(n int) string { f.mu.Lock(); defer f.mu.Unlock(); return f.uris[n] }

// secrets are every string that must stay out of an error: the subject token, the delegated tokens and the secret.
func (f *fakeAPI) secrets(sub string) []string {
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

func noSecretIn(t *testing.T, err error, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("a secret is in the error: %v", err)
		}
	}
}

func mapServiceJSON(slug string) map[string]any {
	return map[string]any{"slug": slug, "name": strings.ToUpper(slug), "description": "About " + slug,
		"endpoint": "https://" + slug + ".example.id", "base_path": "/api", "logo_url": "ignored"}
}

func mapOrgJSON(id string, projects ...map[string]any) map[string]any {
	if projects == nil {
		projects = []map[string]any{}
	}
	return map[string]any{"id": id, "name": "Org " + id, "slug": id, "projects": projects, "projects_truncated": false}
}

func mapProjectJSON(id string, services ...string) map[string]any {
	return map[string]any{"id": id, "name": "Lokasi " + id, "slug": id, "services": services}
}

func stale(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token_stale"`)
	writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "error_code": "token_stale", "message": "stale"})
}

func TestServicesOnePage(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"services": []any{mapServiceJSON("nadi")},
			"organizations": []any{mapOrgJSON("org_hermina", mapProjectJSON("prj_a", "nadi"))},
			"page":          map[string]any{"next_page_token": ""}, "unknown": 1})
	}
	got, err := x.Services(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	want := ServiceMap{
		Services: []MapService{{Slug: "nadi", Name: "NADI", Description: "About nadi", Endpoint: "https://nadi.example.id", BasePath: "/api"}},
		Organizations: []MapOrganization{{ID: "org_hermina", Name: "Org org_hermina", Slug: "org_hermina",
			Projects: []MapProject{{ID: "prj_a", Name: "Lokasi prj_a", Slug: "prj_a", Services: []string{"nadi"}}}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if f.count() != 1 || f.forms[0].Get("scope") != "nice:aud:nice" || f.forms[0].Get("subject_token") != sub {
		t.Fatalf("one exchange for the NICE API: %d %v", f.count(), f.forms)
	}
	if f.calls() != 1 || !strings.HasPrefix(f.uri(0), "/api/v1/me/services?") || f.queries[0].Get("page_size") != "50" || f.queries[0].Has("page_token") {
		t.Fatalf("one call to the service map with page_size 50: %v", f.uris)
	}
	if f.bearers[0] == sub || !strings.HasPrefix(f.bearers[0], "h.") {
		t.Fatalf("the call carries the delegated token, not the subject token: %q", f.bearers[0])
	}
}

func TestServicesReadsEveryPageAndListsAServiceOnce(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		next := ""
		if n < 2 {
			next = fmt.Sprintf("tok-%d", n+1)
		}
		// nadi is listed by the first and the third page, navi by the second.
		svc := []string{"nadi", "navi", "nadi"}[n]
		writeJSON(w, http.StatusOK, map[string]any{"services": []any{mapServiceJSON(svc)},
			"organizations": []any{mapOrgJSON(fmt.Sprintf("org_%d", n), mapProjectJSON(fmt.Sprintf("prj_%d", n), svc))},
			"page":          map[string]any{"next_page_token": next}})
	}
	got, err := x.Services(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	var orgs, slugs []string
	for _, o := range got.Organizations {
		orgs = append(orgs, o.ID)
	}
	for _, s := range got.Services {
		slugs = append(slugs, s.Slug)
	}
	if strings.Join(orgs, ",") != "org_0,org_1,org_2" {
		t.Fatalf("the organizations of all pages in order: %v", orgs)
	}
	if strings.Join(slugs, ",") != "nadi,navi" {
		t.Fatalf("one entry per slug, in slug order: %v", slugs)
	}
	if f.calls() != 3 || f.queries[1].Get("page_token") != "tok-1" || f.queries[2].Get("page_token") != "tok-2" {
		t.Fatalf("the next page token is followed: %v", f.queries)
	}
	if f.count() != 1 {
		t.Fatalf("one exchange for all pages, got %d", f.count())
	}
}

func TestServicesCarriesTruncationAndAnOrganizationWithoutProjects(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		big := mapOrgJSON("org_big", mapProjectJSON("prj_1", "nadi", "navi"))
		big["projects_truncated"] = true
		writeJSON(w, http.StatusOK, map[string]any{"services": []any{mapServiceJSON("navi"), mapServiceJSON("nadi")},
			"organizations": []any{big, mapOrgJSON("org_empty")}})
	}
	got, err := x.Services(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	o := got.Organizations
	if len(o) != 2 || !o[0].ProjectsTruncated || o[1].ProjectsTruncated || len(o[1].Projects) != 0 {
		t.Fatalf("organizations %+v", o)
	}
	if !reflect.DeepEqual(o[0].Projects[0].Services, []string{"nadi", "navi"}) || got.Services[0].Slug != "nadi" {
		t.Fatalf("the services of the project and the map: %+v", got)
	}
}

func TestContextsThenServicesExchangeOnce(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{mapOrgJSON("org_a")}})
	}
	if _, err := x.Contexts(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Services(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	if _, err := x.ServiceOperations(context.Background(), sub, "nadi"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 || f.calls() != 3 {
		t.Fatalf("%d exchanges and %d calls, want 1 and 3", f.count(), f.calls())
	}
	if f.bearers[0] != f.bearers[1] || f.bearers[1] != f.bearers[2] {
		t.Fatal("the three calls carry the one delegated token")
	}
}

func TestServicesExchangesAgainOnceOnAStaleToken(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			stale(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{mapOrgJSON("org_a")}})
	}
	got, err := x.Services(context.Background(), sub)
	if err != nil || len(got.Organizations) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if f.count() != 2 || f.calls() != 2 || f.bearers[0] == f.bearers[1] {
		t.Fatalf("one more exchange and one more call with the new token: %d exchanges, %d calls", f.count(), f.calls())
	}

	f.answer = func(w http.ResponseWriter, r *http.Request, n int) { stale(w) }
	_, err = x.Services(context.Background(), sub)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized || f.calls() != 4 {
		t.Fatalf("a second stale answer is returned: %v, %d calls", err, f.calls())
	}
}

func TestServicesStopsAfterTheLastAllowedPage(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{mapOrgJSON(fmt.Sprintf("org_%d", n))},
			"page": map[string]any{"next_page_token": fmt.Sprintf("tok-%d", n+1)}})
	}
	got, err := x.Services(context.Background(), sub)
	if err == nil || !reflect.DeepEqual(got, ServiceMap{}) || f.calls() != maxContextsPages {
		t.Fatalf("an error and no map after %d pages: %+v %v, %d calls", maxContextsPages, got, err, f.calls())
	}
}

func TestServicesRefusesAPageLargerThanTheBound(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{mapOrgJSON("org_a")}, "page": map[string]any{"next_page_token": "tok-1"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{mapOrgJSON("org_b")}, "padding": strings.Repeat("x", maxContextsBody)})
	}
	got, err := x.Services(context.Background(), sub)
	if err == nil || !reflect.DeepEqual(got, ServiceMap{}) || IsTemporary(err) {
		t.Fatalf("a body over the bound is an error and no map: %+v %v", got, err)
	}
}

func TestServicesErrors(t *testing.T) {
	for _, c := range []struct {
		name      string
		answer    func(w http.ResponseWriter, r *http.Request, n int)
		status    int
		code      string
		temporary bool
	}{
		{"user_required", func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "error_code": "user_required", "message": "a user token is required",
				"request_id": "req_1"})
		}, http.StatusForbidden, "user_required", false},
		{"delegation_not_allowed", func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "error_code": "delegation_not_allowed"})
		}, http.StatusForbidden, "delegation_not_allowed", false},
		{"unavailable", func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": 503, "error_code": "unavailable"})
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
				writeJSON(w, http.StatusOK, map[string]any{"organizations": []any{mapOrgJSON("org_a")}, "page": map[string]any{"next_page_token": "tok-1"}})
				return
			}
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": 502, "error_code": "upstream"})
		}, http.StatusBadGateway, "upstream", true},
		{"redirect", func(w http.ResponseWriter, r *http.Request, n int) {
			http.Redirect(w, r, "https://elsewhere.example/api/v1/me/services", http.StatusFound)
		}, http.StatusFound, "redirect", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, x, sub := newFakeAPI(t)
			f.answer = c.answer
			got, err := x.Services(context.Background(), sub)
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != c.status || ae.Code != c.code || IsTemporary(err) != c.temporary {
				t.Fatalf("got %#v (temporary %v)", err, IsTemporary(err))
			}
			if !reflect.DeepEqual(got, ServiceMap{}) {
				t.Fatalf("no map on an error: %+v", got)
			}
			if c.name == "user_required" && (ae.Message != "a user token is required" || ae.RequestID != "req_1") {
				t.Fatalf("message and request ID: %+v", ae)
			}
			if strings.Contains(err.Error(), "raw proxy page") {
				t.Fatalf("the raw body is in the error: %v", err)
			}
			noSecretIn(t, err, f.secrets(sub))
		})
	}
}

func TestServicesReportsANiceThatDoesNotAnswerAsTemporary(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) { panic(http.ErrAbortHandler) }
	got, err := x.Services(context.Background(), sub)
	if !IsTemporary(err) || !reflect.DeepEqual(got, ServiceMap{}) {
		t.Fatalf("a dropped connection is temporary: %v", err)
	}
	noSecretIn(t, err, f.secrets(sub))
}

func TestServicesReturnsTheRefusalOfTheExchange(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.refuse = "invalid_grant"
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) { t.Error("NICE API called without a token") }
	_, err := x.Services(context.Background(), sub)
	var ge *GrantError
	if !errors.As(err, &ge) || ge.Code != "invalid_grant" || f.calls() != 0 {
		t.Fatalf("the GrantError of the exchange: %v", err)
	}
	noSecretIn(t, err, []string{sub, "s3cret"})
}

func nadiOperationsJSON() map[string]any {
	return map[string]any{
		"service": "nadi",
		"operations": []any{
			map[string]any{"key": "listDevices", "method": "GET", "path": "/devices", "summary": "List devices",
				"permission": "nadi.devices.read", "tag": "devices",
				"headers":        []any{map[string]any{"name": "X-Region", "value": "id"}},
				"request_fields": []any{map[string]any{"location": "query", "name": "status", "type": "string"}}},
			map[string]any{"key": "getDevice", "method": "GET", "path": "/devices/{id}", "summary": "Get a device",
				"permission": "nadi.devices.read", "tag": "devices",
				"request_fields": []any{map[string]any{"location": "path", "name": "id", "required": true}}},
			map[string]any{"key": "deleteDevice", "method": "DELETE", "path": "/devices/{id}", "summary": "Delete a device",
				"permission": "nadi.devices.delete", "tag": "devices", "sensitive": true, "responses": []any{}},
		},
		"tags":    []any{map[string]any{"name": "devices", "description": "IoT devices"}, map[string]any{"name": "unused"}},
		"unknown": true,
	}
}

func TestServiceOperationsListsTheOperationsOfAService(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) { writeJSON(w, http.StatusOK, nadiOperationsJSON()) }
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil {
		t.Fatal(err)
	}
	want := ServiceOperations{
		Service: "nadi",
		Operations: []ServiceOperation{
			{Key: "listDevices", Method: "GET", Path: "/devices", Summary: "List devices", Permission: "nadi.devices.read", Tag: "devices",
				Headers:       []OperationHeader{{Name: "X-Region", Value: "id"}},
				RequestFields: []RequestField{{Location: "query", Name: "status", Type: "string"}}},
			{Key: "getDevice", Method: "GET", Path: "/devices/{id}", Summary: "Get a device", Permission: "nadi.devices.read", Tag: "devices",
				RequestFields: []RequestField{{Location: "path", Name: "id", Required: true}}},
			{Key: "deleteDevice", Method: "DELETE", Path: "/devices/{id}", Summary: "Delete a device", Permission: "nadi.devices.delete",
				Tag: "devices", Sensitive: true},
		},
		Tags: []OperationTag{{Name: "devices", Description: "IoT devices"}, {Name: "unused"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if f.count() != 1 || f.forms[0].Get("scope") != "nice:aud:nice" {
		t.Fatalf("one exchange for the NICE API: %d %v", f.count(), f.forms)
	}
	if f.calls() != 1 || f.uri(0) != "/api/v1/me/services/nadi/operations?page_size=500" || f.bearers[0] == sub {
		t.Fatalf("one call with the delegated token: %v", f.uris)
	}
}

func TestServiceOperationsRefusesASlugThatIsNoSegment(t *testing.T) {
	for _, slug := range []string{"", ".", ".."} {
		f, x, sub := newFakeAPI(t)
		f.answer = func(w http.ResponseWriter, r *http.Request, n int) { t.Error("NICE called") }
		got, err := x.ServiceOperations(context.Background(), sub, slug)
		if err == nil || !reflect.DeepEqual(got, ServiceOperations{}) {
			t.Fatalf("%q: refused, got %+v %v", slug, got, err)
		}
		if f.count() != 0 || f.calls() != 0 {
			t.Fatalf("%q: nothing is exchanged or sent: %d exchanges, %d calls", slug, f.count(), f.calls())
		}
	}
}

func TestServiceOperationsSendsTheSlugAsOneEscapedSegment(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "error_code": "not_found"})
	}
	for _, c := range []struct{ slug, uri string }{
		{"nadi/../../organizations", "/api/v1/me/services/nadi%2F..%2F..%2Forganizations/operations?page_size=500"},
		{"a/b", "/api/v1/me/services/a%2Fb/operations?page_size=500"},
		{"na di?x=1#y", "/api/v1/me/services/na%20di%3Fx=1%23y/operations?page_size=500"},
	} {
		n := f.calls()
		if _, err := x.ServiceOperations(context.Background(), sub, c.slug); err == nil {
			t.Fatalf("%q: the 404 of NICE is returned", c.slug)
		}
		if f.calls() != n+1 || f.uri(n) != c.uri {
			t.Fatalf("%q: one call to %s, got %v", c.slug, c.uri, f.uris[n:])
		}
	}
}

func TestServiceOperationsErrors(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		f, x, sub := newFakeAPI(t)
		f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "error_code": "not_found", "message": "service not found"})
		}
		got, err := x.ServiceOperations(context.Background(), sub, "nasa")
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != http.StatusNotFound || ae.Code != "not_found" || IsTemporary(err) {
			t.Fatalf("a typed 404 not_found: %#v", err)
		}
		if !reflect.DeepEqual(got, ServiceOperations{}) {
			t.Fatalf("no operations on an error: %+v", got)
		}
		noSecretIn(t, err, f.secrets(sub))
	})
	t.Run("unavailable", func(t *testing.T) {
		f, x, sub := newFakeAPI(t)
		f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": 503, "error_code": "unavailable"})
		}
		_, err := x.ServiceOperations(context.Background(), sub, "nadi")
		var ae *APIError
		if !IsTemporary(err) || !errors.As(err, &ae) || ae.Status != http.StatusServiceUnavailable {
			t.Fatalf("a 503 is temporary and still an APIError: %#v", err)
		}
		noSecretIn(t, err, f.secrets(sub))
	})
	t.Run("nice does not answer", func(t *testing.T) {
		f, x, sub := newFakeAPI(t)
		f.answer = func(w http.ResponseWriter, r *http.Request, n int) { panic(http.ErrAbortHandler) }
		_, err := x.ServiceOperations(context.Background(), sub, "nadi")
		if !IsTemporary(err) {
			t.Fatalf("a dropped connection is temporary: %v", err)
		}
		noSecretIn(t, err, f.secrets(sub))
	})
	t.Run("stale once", func(t *testing.T) {
		f, x, sub := newFakeAPI(t)
		f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
			if n == 0 {
				stale(w)
				return
			}
			writeJSON(w, http.StatusOK, nadiOperationsJSON())
		}
		got, err := x.ServiceOperations(context.Background(), sub, "nadi")
		if err != nil || len(got.Operations) != 3 || f.count() != 2 || f.calls() != 2 {
			t.Fatalf("one more exchange and one more call: %v, %d exchanges, %d calls", err, f.count(), f.calls())
		}
	})
	t.Run("exchange refused", func(t *testing.T) {
		f, x, sub := newFakeAPI(t)
		f.refuse = "invalid_grant"
		f.answer = func(w http.ResponseWriter, r *http.Request, n int) { t.Error("NICE API called without a token") }
		_, err := x.ServiceOperations(context.Background(), sub, "nadi")
		var ge *GrantError
		if !errors.As(err, &ge) || ge.Code != "invalid_grant" || f.calls() != 0 {
			t.Fatalf("the GrantError of the exchange: %v", err)
		}
		noSecretIn(t, err, []string{sub, "s3cret"})
	})
}

func TestServiceOperationsRefusesABodyLargerThanTheBound(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"service": "nadi", "padding": strings.Repeat("x", maxOperationsBody)})
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err == nil || !reflect.DeepEqual(got, ServiceOperations{}) || IsTemporary(err) {
		t.Fatalf("a body over the bound is an error and no operations: %+v %v", got, err)
	}
}
