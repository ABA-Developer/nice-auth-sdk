package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// seenCall is one request the fake service received.
type seenCall struct {
	method string
	uri    string // the request target as sent, still escaped
	header http.Header
	body   string
}

// fakeService plays a nice_token service such as nadi: it records every request and answers with answer.
type fakeService struct {
	srv *httptest.Server

	mu    sync.Mutex
	calls []seenCall
	// answer serves the request with index n (from 0); nil answers 200.
	answer func(w http.ResponseWriter, r *http.Request, n int)
}

func newFakeService(t *testing.T) *fakeService {
	t.Helper()
	s := &fakeService{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		n := len(s.calls)
		s.calls = append(s.calls, seenCall{method: r.Method, uri: r.RequestURI, header: r.Header.Clone(), body: string(raw)})
		answer := s.answer
		s.mu.Unlock()
		if answer == nil {
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return
		}
		answer(w, r, n)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *fakeService) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.calls) }

func (s *fakeService) call(n int) seenCall { s.mu.Lock(); defer s.mu.Unlock(); return s.calls[n] }

// scopeOf reads the scope the fake exchange wrote into the token of an Authorization header.
func scopeOf(authorization string) string {
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 {
		return ""
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Scope
}

// callFixture is NICE, the service nadi and a subject token of the user for the service of the client (naia) in
// the project where it is active.
type callFixture struct {
	nice *fakeExchange
	svc  *fakeService
	x    *ExchangeClient
	sub  string
	nadi MapService
}

func newCallFixture(t *testing.T) *callFixture {
	t.Helper()
	clk := newClock()
	f := &callFixture{nice: newFakeExchange(t, clk), svc: newFakeService(t)}
	f.x = exchangeClient(t, f.nice)
	f.sub = subject(clk, "usr_1", "org_hermina", "prj_p0", 30*time.Minute)
	f.nadi = MapService{Slug: "nadi", Name: "NADI", Endpoint: f.svc.srv.URL, BasePath: "/api"}
	return f
}

var (
	opListDevices  = ServiceOperation{Key: "listDevices", Method: "GET", Path: "/devices", Permission: "nadi.devices.read"}
	opGetDevice    = ServiceOperation{Key: "getDevice", Method: "GET", Path: "/devices/{id}", Permission: "nadi.devices.read"}
	opCreateDevice = ServiceOperation{Key: "createDevice", Method: "POST", Path: "/devices", Permission: "nadi.devices.create"}
)

func (f *callFixture) do(t *testing.T, call OperationCall) *http.Response {
	t.Helper()
	resp, err := f.x.CallOperation(context.Background(), f.sub, call)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestCallOperationSendsToTheEndpointBasePathAndPath(t *testing.T) {
	f := newCallFixture(t)
	resp := f.do(t, OperationCall{Service: f.nadi, Operation: opListDevices, Org: "org_hermina", Project: "prj_a",
		Query: url.Values{"status": {"active"}, "q": {"a b"}}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := f.svc.call(0)
	if got.method != http.MethodGet || got.uri != "/api/devices?q=a+b&status=active" {
		t.Fatalf("GET endpoint + base path + path with the query: %s %s", got.method, got.uri)
	}
	if f.nice.count() != 1 || f.nice.forms[0].Get("scope") != "nice:aud:nadi nice:org:org_hermina nice:prj:prj_a" ||
		f.nice.forms[0].Get("subject_token") != f.sub {
		t.Fatalf("one exchange for nadi in the project: %v", f.nice.forms)
	}
	if auth := got.header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer h.") || auth == "Bearer "+f.sub ||
		scopeOf(auth) != "nice:aud:nadi nice:org:org_hermina nice:prj:prj_a" {
		t.Fatalf("the call carries the exchanged token of the project: %q", auth)
	}
}

func TestCallOperationJoinsAnEndpointAndABasePathWithTrailingSlashes(t *testing.T) {
	f := newCallFixture(t)
	f.do(t, OperationCall{Service: MapService{Slug: "nadi", Endpoint: f.svc.srv.URL + "/v1/", BasePath: "/api/"}, Operation: opListDevices, Project: "prj_a"})
	f.do(t, OperationCall{Service: MapService{Slug: "nadi", Endpoint: f.svc.srv.URL}, Operation: opListDevices, Project: "prj_a"})
	f.do(t, OperationCall{Service: f.nadi, Operation: ServiceOperation{Method: "get", Path: "/devices"}, Project: "prj_a"})
	if a, b, c := f.svc.call(0), f.svc.call(1), f.svc.call(2); a.uri != "/v1/api/devices" || b.uri != "/devices" || c.uri != "/api/devices" || c.method != http.MethodGet {
		t.Fatalf("addresses %q, %q, %q (%s)", a.uri, b.uri, c.uri, c.method)
	}
}

func TestCallOperationExchangesOncePerProject(t *testing.T) {
	f := newCallFixture(t)
	projects := map[string]string{"A": "prj_a", "B": "prj_b", "C": "prj_c"}
	var wg sync.WaitGroup
	for loc, prj := range projects {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.x.CallOperation(context.Background(), f.sub, OperationCall{Service: f.nadi, Operation: opListDevices,
				Org: "org_hermina", Project: prj, Query: url.Values{"loc": {loc}}})
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	if f.nice.count() != 3 || f.svc.count() != 3 {
		t.Fatalf("%d exchanges and %d calls, want 3 and 3", f.nice.count(), f.svc.count())
	}
	for n := 0; n < 3; n++ {
		c := f.svc.call(n)
		u, _ := url.Parse(c.uri)
		want := "nice:aud:nadi nice:org:org_hermina nice:prj:" + projects[u.Query().Get("loc")]
		if got := scopeOf(c.header.Get("Authorization")); got != want {
			t.Fatalf("the call of %s carries the token of its own project: %q, want %q", u.Query().Get("loc"), got, want)
		}
	}
}

func TestCallOperationExchangesOnceForTwoCallsInOneProject(t *testing.T) {
	f := newCallFixture(t)
	f.do(t, OperationCall{Service: f.nadi, Operation: opListDevices, Org: "org_hermina", Project: "prj_a"})
	f.do(t, OperationCall{Service: f.nadi, Operation: opGetDevice, Org: "org_hermina", Project: "prj_a", PathParams: map[string]string{"id": "dev-1"}})
	if f.nice.count() != 1 || f.svc.count() != 2 {
		t.Fatalf("%d exchanges and %d calls, want 1 and 2", f.nice.count(), f.svc.count())
	}
	if a, b := f.svc.call(0), f.svc.call(1); a.header.Get("Authorization") != b.header.Get("Authorization") {
		t.Fatal("both calls carry the kept token")
	}
}

func TestCallOperationSendsTheBodyAgainOnAStaleToken(t *testing.T) {
	f := newCallFixture(t)
	f.svc.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			stale(w)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": "dev-9"})
	}
	const body = `{"name":"Monitor 9","status":"active"}`
	resp := f.do(t, OperationCall{Service: f.nadi, Operation: opCreateDevice, Project: "prj_a", Body: []byte(body)})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the second answer is returned: %d", resp.StatusCode)
	}
	if f.nice.count() != 2 || f.svc.count() != 2 {
		t.Fatalf("one more exchange and one more call: %d exchanges, %d calls", f.nice.count(), f.svc.count())
	}
	a, b := f.svc.call(0), f.svc.call(1)
	if a.body != body || b.body != body || a.method != http.MethodPost || b.uri != "/api/devices" {
		t.Fatalf("the same body is sent twice: %q then %q", a.body, b.body)
	}
	if a.header.Get("Authorization") == b.header.Get("Authorization") {
		t.Fatal("the second call carries the new token")
	}

	// A second stale answer is returned as it is: one retry only.
	f.svc.answer = func(w http.ResponseWriter, r *http.Request, n int) { stale(w) }
	resp = f.do(t, OperationCall{Service: f.nadi, Operation: opCreateDevice, Project: "prj_a", Body: []byte(body)})
	if resp.StatusCode != http.StatusUnauthorized || f.svc.count() != 4 {
		t.Fatalf("status %d after %d calls", resp.StatusCode, f.svc.count())
	}
}

func TestCallOperationFillsThePathParameters(t *testing.T) {
	f := newCallFixture(t)
	f.do(t, OperationCall{Service: f.nadi, Operation: opGetDevice, Project: "prj_a", PathParams: map[string]string{"id": "dev 01"}})
	f.do(t, OperationCall{Service: f.nadi, Operation: opGetDevice, Project: "prj_a", PathParams: map[string]string{"id": "a?b#c%2Fd"}})
	two := ServiceOperation{Method: "GET", Path: "/sites/{site}/devices/{id}.json"}
	f.do(t, OperationCall{Service: f.nadi, Operation: two, Project: "prj_a", PathParams: map[string]string{"site": "rs utara", "id": "7"}})
	for n, want := range []string{"/api/devices/dev%2001", "/api/devices/a%3Fb%23c%252Fd", "/api/sites/rs%20utara/devices/7.json"} {
		if got := f.svc.call(n).uri; got != want {
			t.Fatalf("call %d went to %q, want %q", n, got, want)
		}
	}
}

func TestCallOperationRefusesPathParametersBeforeAnyExchange(t *testing.T) {
	for _, c := range []struct {
		name   string
		op     ServiceOperation
		params map[string]string
		names  string // must be in the error
	}{
		{"missing", opGetDevice, nil, "id"},
		{"missing among others", ServiceOperation{Method: "GET", Path: "/sites/{site}/devices/{id}"}, map[string]string{"site": "s1"}, "id"},
		{"unknown name", opGetDevice, map[string]string{"id": "dev-1", "serial": "SN-1"}, "serial"},
		{"unknown name without placeholders", opListDevices, map[string]string{"serial": "SN-1"}, "serial"},
		{"empty", opGetDevice, map[string]string{"id": ""}, "id"},
		{"blank", opGetDevice, map[string]string{"id": "  "}, "id"},
		{"slash", opGetDevice, map[string]string{"id": "a/b"}, "id"},
		{"backslash", opGetDevice, map[string]string{"id": `a\b`}, "id"},
		{"dot", opGetDevice, map[string]string{"id": "."}, "id"},
		{"dot dot", opGetDevice, map[string]string{"id": ".."}, "id"},
		{"control character", opGetDevice, map[string]string{"id": "a\nb"}, "id"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCallFixture(t)
			resp, err := f.x.CallOperation(context.Background(), f.sub, OperationCall{Service: f.nadi, Operation: c.op, Project: "prj_a", PathParams: c.params})
			if resp != nil || !errors.Is(err, ErrInvalidOperationCall) || !strings.Contains(err.Error(), c.names) {
				t.Fatalf("an ErrInvalidOperationCall that names %s: %v", c.names, err)
			}
			for _, v := range c.params {
				if len(v) > 2 && strings.Contains(err.Error(), v) {
					t.Fatalf("the error names the parameter, not its value: %v", err)
				}
			}
			if f.nice.count() != 0 || f.svc.count() != 0 {
				t.Fatalf("no exchange and no call: %d exchanges, %d calls", f.nice.count(), f.svc.count())
			}
		})
	}
}

func TestCallOperationRefusesAnIncompleteCallBeforeAnyExchange(t *testing.T) {
	f := newCallFixture(t)
	for name, call := range map[string]OperationCall{
		"no slug":                 {Service: MapService{Endpoint: f.svc.srv.URL}, Operation: opListDevices},
		"the NICE API":            {Service: MapService{Slug: "nice", Endpoint: f.svc.srv.URL}, Operation: opListDevices},
		"no endpoint":             {Service: MapService{Slug: "nadi"}, Operation: opListDevices},
		"endpoint without a host": {Service: MapService{Slug: "nadi", Endpoint: "nadi.example.id"}, Operation: opListDevices},
		"endpoint with a query":   {Service: MapService{Slug: "nadi", Endpoint: f.svc.srv.URL + "/?to="}, Operation: opListDevices},
		"endpoint with a user":    {Service: MapService{Slug: "nadi", Endpoint: "https://nadi.example.id@elsewhere.example"}, Operation: opListDevices},
		"no method":               {Service: f.nadi, Operation: ServiceOperation{Path: "/devices"}},
		"a method with a space":   {Service: f.nadi, Operation: ServiceOperation{Method: "GET /x", Path: "/devices"}},
		"no path":                 {Service: f.nadi, Operation: ServiceOperation{Method: "GET"}},
		"a path that moves the host": {Service: MapService{Slug: "nadi", Endpoint: f.svc.srv.URL},
			Operation: ServiceOperation{Method: "GET", Path: ".elsewhere.example/devices"}},
		"a base path that moves the host": {Service: MapService{Slug: "nadi", Endpoint: f.svc.srv.URL, BasePath: "@elsewhere.example"}, Operation: opListDevices},
	} {
		call.Project = "prj_a"
		resp, err := f.x.CallOperation(context.Background(), f.sub, call)
		if resp != nil || !errors.Is(err, ErrInvalidOperationCall) {
			t.Fatalf("%s: an ErrInvalidOperationCall, got %v", name, err)
		}
	}
	if f.nice.count() != 0 || f.svc.count() != 0 {
		t.Fatalf("no exchange and no call: %d exchanges, %d calls", f.nice.count(), f.svc.count())
	}
}

func TestCallOperationHeadersOfTheOperationReplaceTheCallers(t *testing.T) {
	f := newCallFixture(t)
	op := opListDevices
	op.Headers = []OperationHeader{{Name: "X-Region", Value: "id"}, {Name: "X-Api-Version", Value: "2"}}
	// The caller writes the name in another case, straight into the map.
	f.do(t, OperationCall{Service: f.nadi, Operation: op, Project: "prj_a",
		Header: http.Header{"x-region": {"sg"}, "X-Trace": {"t-1"}, "Accept": {"application/json"}}})
	got := f.svc.call(0).header
	if v := got.Values("X-Region"); len(v) != 1 || v[0] != "id" {
		t.Fatalf("the header of the operation replaces the caller's: %v", v)
	}
	if got.Get("X-Api-Version") != "2" || got.Get("X-Trace") != "t-1" || got.Get("Accept") != "application/json" {
		t.Fatalf("the other headers are sent: %v", got)
	}
	if got.Get("Content-Type") != "" {
		t.Fatalf("no content type without a body: %q", got.Get("Content-Type"))
	}
}

func TestCallOperationSetsAuthorizationItself(t *testing.T) {
	f := newCallFixture(t)
	op := opListDevices
	op.Headers = []OperationHeader{{Name: "Authorization", Value: "Bearer of-the-catalog"}}
	f.do(t, OperationCall{Service: f.nadi, Operation: op, Project: "prj_a",
		Header: http.Header{"authorization": {"Bearer of-the-caller"}, "Authorization": {"Bearer of-the-caller-2"}}})
	v := f.svc.call(0).header.Values("Authorization")
	if len(v) != 1 || !strings.HasPrefix(v[0], "Bearer h.") || scopeOf(v[0]) != "nice:aud:nadi nice:prj:prj_a" {
		t.Fatalf("only the exchanged token of the service is sent: %v", v)
	}
}

func TestCallOperationSendsTheBodyAsItIs(t *testing.T) {
	f := newCallFixture(t)
	const body = `{"name":"Monitor 9"}`
	f.do(t, OperationCall{Service: f.nadi, Operation: opCreateDevice, Project: "prj_a", Body: []byte(body)})
	f.do(t, OperationCall{Service: f.nadi, Operation: opCreateDevice, Project: "prj_a", Body: []byte("a,b\n1,2\n"),
		Header: http.Header{"content-type": {"text/csv"}}})
	a, b := f.svc.call(0), f.svc.call(1)
	if a.method != http.MethodPost || a.body != body || a.header.Get("Content-Type") != "application/json" {
		t.Fatalf("a body without a content type is JSON: %q %q", a.body, a.header.Get("Content-Type"))
	}
	if v := b.header.Values("Content-Type"); b.body != "a,b\n1,2\n" || len(v) != 1 || v[0] != "text/csv" {
		t.Fatalf("the content type of the caller is kept: %q %v", b.body, v)
	}
}

func TestCallOperationReturnsTheAnswerOfTheServiceAsItIs(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   map[string]any
	}{
		{"permission denied", http.StatusForbidden, map[string]any{"error_code": "permission_denied"}},
		{"permissions unavailable", http.StatusServiceUnavailable, map[string]any{"error_code": "temporarily_unavailable", "reason": "permissions_unavailable"}},
		{"not found", http.StatusNotFound, map[string]any{"error_code": "not_found"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCallFixture(t)
			f.svc.answer = func(w http.ResponseWriter, r *http.Request, n int) { writeJSON(w, c.status, c.body) }
			resp, err := f.x.CallOperation(context.Background(), f.sub, OperationCall{Service: f.nadi, Operation: opListDevices, Project: "prj_b"})
			if err != nil {
				t.Fatalf("the answer of the service is not an error: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			var got map[string]any
			if resp.StatusCode != c.status || json.NewDecoder(resp.Body).Decode(&got) != nil || got["error_code"] != c.body["error_code"] {
				t.Fatalf("status %d and the body of the service, unread: %d %v", c.status, resp.StatusCode, got)
			}
			if f.svc.count() != 1 || f.nice.count() != 1 {
				t.Fatalf("one call and one exchange: %d and %d", f.svc.count(), f.nice.count())
			}
		})
	}
}

func TestCallOperationReturnsTheRefusalOfTheExchange(t *testing.T) {
	f := newCallFixture(t)
	// NICE refuses a sign-in token as the subject of an exchange for another service.
	f.nice.refuse = "invalid_grant"
	resp, err := f.x.CallOperation(context.Background(), f.sub, OperationCall{Service: f.nadi, Operation: opListDevices, Project: "prj_a"})
	var ge *GrantError
	if resp != nil || !errors.As(err, &ge) || ge.Code != "invalid_grant" || errors.Is(err, ErrInvalidOperationCall) {
		t.Fatalf("the GrantError of the exchange: %v", err)
	}
	if f.svc.count() != 0 {
		t.Fatalf("the service is not called: %d calls", f.svc.count())
	}
	noSecretIn(t, err, []string{f.sub, "s3cret"})
}

func TestCallOperationRefusesPlainHTTPThatIsNotLoopback(t *testing.T) {
	f := newCallFixture(t)
	svc := MapService{Slug: "nadi", Endpoint: "http://nadi.example.id", BasePath: "/api"}
	resp, err := f.x.CallOperation(context.Background(), f.sub, OperationCall{Service: svc, Operation: opListDevices, Project: "prj_a"})
	if resp != nil || err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("the address rule of the exchange mode: %v", err)
	}
	if f.nice.count() != 0 {
		t.Fatalf("refused before any exchange: %d exchanges", f.nice.count())
	}
	noSecretIn(t, err, []string{f.sub, "s3cret"})
}

func TestCallOperationKeepsTokensOutOfAnError(t *testing.T) {
	f := newCallFixture(t)
	// The service drops the connection.
	f.svc.answer = func(w http.ResponseWriter, r *http.Request, n int) { panic(http.ErrAbortHandler) }
	resp, err := f.x.CallOperation(context.Background(), f.sub, OperationCall{Service: f.nadi, Operation: opCreateDevice, Project: "prj_a",
		Body: []byte(`{"name":"Monitor 9"}`), Query: url.Values{"dry_run": {"1"}}})
	if f.svc.count() == 0 {
		t.Fatal("the service was not called")
	}
	bearer := strings.TrimPrefix(f.svc.call(0).header.Get("Authorization"), "Bearer ")
	if resp != nil || err == nil || bearer == "" {
		t.Fatalf("a service that does not answer is an error: %v", err)
	}
	noSecretIn(t, err, []string{f.sub, "s3cret", bearer})
}
