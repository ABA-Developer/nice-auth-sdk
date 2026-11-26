package credentials

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// schemasAnswer answers the keys of r: a schema for each key that starts with "ok", the others missing.
func schemasAnswer(w http.ResponseWriter, r *http.Request) {
	schemas := []any{}
	missing := []string{}
	for _, k := range r.URL.Query()["keys"] {
		if strings.HasPrefix(k, "ok") {
			schemas = append(schemas, map[string]any{"key": k, "input_schema": map[string]any{"type": "object"},
				"responses": map[string]any{"200": map[string]any{"schema": map[string]any{"type": "array"}}}, "truncated": k == "ok-cut"})
		} else {
			missing = append(missing, k)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"service": "nadi", "schemas": schemas, "missing": missing})
}

func TestOperationSchemasReturnsSchemasAndMissingKeys(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"service": "nadi",
			"schemas": []any{map[string]any{"key": "listDevices", "input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
				"responses": map[string]any{}, "truncated": true}}, "missing": []string{"deleteDevice"}})
	}
	got, err := x.OperationSchemas(context.Background(), sub, "nadi", []string{"listDevices", "deleteDevice"})
	if err != nil || got.Service != "nadi" || len(got.Schemas) != 1 || got.Schemas[0].Key != "listDevices" || !got.Schemas[0].Truncated ||
		string(got.Schemas[0].InputSchema) != `{"properties":{},"type":"object"}` || string(got.Schemas[0].Responses) != `{}` ||
		!reflect.DeepEqual(got.Missing, []string{"deleteDevice"}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if q := f.queries[0]["keys"]; !reflect.DeepEqual(q, []string{"listDevices", "deleteDevice"}) || f.bearers[0] == sub {
		t.Fatalf("keys %v", q)
	}
}

func TestOperationSchemasSplitsKeysByTwenty(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) { schemasAnswer(w, r) }
	var keys []string
	for i := range 45 {
		keys = append(keys, fmt.Sprintf("ok%02d", i))
	}
	keys = append(keys, "ok00", "gone", "gone")
	got, err := x.OperationSchemas(context.Background(), sub, "nadi", keys)
	if err != nil || len(got.Schemas) != 45 || got.Schemas[0].Key != "ok00" || got.Schemas[44].Key != "ok44" ||
		!reflect.DeepEqual(got.Missing, []string{"gone"}) {
		t.Fatalf("got %d schemas, missing %v, %v", len(got.Schemas), got.Missing, err)
	}
	if f.calls() != 3 || len(f.queries[0]["keys"]) != 20 || len(f.queries[1]["keys"]) != 20 || len(f.queries[2]["keys"]) != 6 {
		t.Fatalf("calls %v", f.uris)
	}
	if f.count() != 1 {
		t.Fatalf("one exchange: %d", f.count())
	}
}

func TestOperationSchemasReturnsNothingWhenOneRequestFails(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 1 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": 503, "error_code": "unavailable"})
			return
		}
		schemasAnswer(w, r)
	}
	var keys []string
	for i := range 45 {
		keys = append(keys, fmt.Sprintf("ok%02d", i))
	}
	got, err := x.OperationSchemas(context.Background(), sub, "nadi", keys)
	if !IsTemporary(err) || got.Schemas != nil || got.Missing != nil {
		t.Fatalf("got %+v, %v", got, err)
	}
	noSecretIn(t, err, f.secrets(sub))
}

func TestOperationSchemasRefusesBeforeAnyCall(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) { t.Error("NICE called") }
	for _, c := range []struct {
		slug string
		keys []string
	}{{"", []string{"a"}}, {"..", []string{"a"}}, {"nadi", nil}, {"nadi", []string{"a", ""}}} {
		if _, err := x.OperationSchemas(context.Background(), sub, c.slug, c.keys); err == nil {
			t.Fatalf("%q %q: refused", c.slug, c.keys)
		}
	}
	if f.count() != 0 || f.calls() != 0 {
		t.Fatalf("%d exchanges, %d calls", f.count(), f.calls())
	}
}

func TestOperationSchemasOfAnOlderNICEIsAnAPIError(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "error_code": "not_found"})
	}
	var ae *APIError
	if _, err := x.OperationSchemas(context.Background(), sub, "nadi", []string{"a"}); !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("got %v", err)
	}
}

func TestOperationSchemasKeepsTheBytesOfTheSchema(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	const input = `{"type":"object","properties":{"z":{"type":"integer"},"a":{"type":"number","enum":[12345678901234567890]}}}`
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"service":"nadi","schemas":[{"key":"a","input_schema":` + input + `,"responses":{},"truncated":false}],"missing":[]}`))
	}
	got, err := x.OperationSchemas(context.Background(), sub, "nadi", []string{"a"})
	if err != nil || string(got.Schemas[0].InputSchema) != input {
		t.Fatalf("got %s, %v", got.Schemas[0].InputSchema, err)
	}
}

func TestResponseSchemaPicksExactThenRangeThenDefault(t *testing.T) {
	s := OperationSchema{Responses: []byte(`{"200":{"schema":{"title":"ok"}},"2XX":{"schema":{"title":"range"}},` +
		`"4xx":{"schema":{"title":"client"}},"default":{"schema":{"title":"default"}},"204":{"description":"empty"}}`)}
	for status, want := range map[int]string{200: `{"title":"ok"}`, 201: `{"title":"range"}`, 404: `{"title":"client"}`, 503: `{"title":"default"}`} {
		if got := string(s.ResponseSchema(status)); got != want {
			t.Fatalf("%d: %s, want %s", status, got, want)
		}
	}
	if got := s.ResponseSchema(204); got != nil {
		t.Fatalf("204 without schema: %s", got)
	}
	if got := (OperationSchema{Responses: []byte(`{}`)}).ResponseSchema(200); got != nil {
		t.Fatalf("no responses: %s", got)
	}
}
