package credentials

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// writeGzipJSON answers v as gzip-compressed JSON.
func writeGzipJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_ = json.NewEncoder(zw).Encode(v)
	_ = zw.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// opsPage is one page of n operations named op<first>…, with tag as its ETag and next as its next page token.
func opsPage(first, n int, next string) map[string]any {
	ops := []map[string]any{}
	for i := first; i < first+n; i++ {
		ops = append(ops, map[string]any{"key": fmt.Sprintf("op%d", i), "method": "GET", "path": fmt.Sprintf("/x/%d", i),
			"permission": "nadi.x.read", "headers": []any{}, "request_fields": []any{}})
	}
	out := map[string]any{"service": "nadi", "catalog_version": "12", "operations": ops, "tags": []any{map[string]any{"name": "x"}}}
	if next != "" {
		out["page"] = map[string]any{"next_page_token": next}
	}
	return out
}

func keysOfOps(ops ServiceOperations) []string {
	out := []string{}
	for _, o := range ops.Operations {
		out = append(out, o.Key)
	}
	return out
}

func TestServiceOperationsCarriesTheRichFieldsVersionAndETag(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("ETag", `W/"12-3f9a0c1d2e4b"`)
		writeJSON(w, http.StatusOK, map[string]any{"service": "nadi", "catalog_version": "12", "list_digest": "3f9a0c1d2e4b",
			"operations": []any{map[string]any{"key": "listDevices", "method": "GET", "path": "/devices", "summary": "List",
				"description": "Devices of the project.", "permission": "nadi.devices.read", "headers": []any{},
				"request_fields": []any{map[string]any{"location": "query", "name": "status", "type": "string",
					"description": "State of the device", "format": "slug", "enum": []any{"online", 2, true}, "enum_truncated": true}}}},
			"tags": []any{}})
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil {
		t.Fatal(err)
	}
	want := RequestField{Location: "query", Name: "status", Type: "string", Description: "State of the device", Format: "slug",
		Enum: []any{"online", float64(2), true}, EnumTruncated: true}
	if got.CatalogVersion != 12 || got.ETag != `W/"12-3f9a0c1d2e4b"` || got.Operations[0].Description != "Devices of the project." ||
		!reflect.DeepEqual(got.Operations[0].RequestFields[0], want) {
		t.Fatalf("got %+v", got)
	}
}

func TestServiceOperationsReadsAnOlderNICEWithoutTheNewFields(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, map[string]any{"service": "nadi", "operations": []any{map[string]any{"key": "a", "method": "GET",
			"path": "/a", "headers": []any{}, "request_fields": []any{map[string]any{"location": "path", "name": "id", "required": true}}}},
			"tags": []any{}})
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil || got.CatalogVersion != 0 || got.ETag != "" || len(got.Operations) != 1 || got.Operations[0].RequestFields[0].Enum != nil {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestServiceOperationsTakesAGzipAnswerAndBoundsItAfterDecompression(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("Accept-Encoding = %q", r.Header.Get("Accept-Encoding"))
		}
		writeGzipJSON(w, http.StatusOK, opsPage(0, 3, ""))
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil || !reflect.DeepEqual(keysOfOps(got), []string{"op0", "op1", "op2"}) {
		t.Fatalf("got %v, %v", keysOfOps(got), err)
	}

	// A small compressed body that grows over 16 MiB is refused.
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		page := opsPage(0, 1, "")
		page["service"] = strings.Repeat("a", maxOperationsBody+10)
		writeGzipJSON(w, http.StatusOK, page)
	}
	if got, err := x.ServiceOperations(context.Background(), sub, "nadi"); err == nil || !strings.Contains(err.Error(), "larger than 16 MiB") ||
		got.Operations != nil {
		t.Fatalf("a body over the bound after decompression: %v", err)
	}
}

func TestServiceMapTakesAGzipAnswer(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeGzipJSON(w, http.StatusOK, map[string]any{"services": []any{map[string]any{"slug": "nadi", "endpoint": "https://nadi.test"}},
			"organizations": []any{}, "page": map[string]any{}})
	}
	m, err := x.Services(context.Background(), sub)
	if err != nil || len(m.Services) != 1 || m.Services[0].Slug != "nadi" {
		t.Fatalf("map = %+v, %v", m, err)
	}
}

func TestServiceOperationsReadsEveryPage(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("ETag", `W/"12-aaa"`)
		switch r.URL.Query().Get("page_token") {
		case "":
			writeJSON(w, http.StatusOK, opsPage(0, 500, "op499"))
		case "op499":
			writeJSON(w, http.StatusOK, opsPage(500, 500, "op999"))
		case "op999":
			writeJSON(w, http.StatusOK, opsPage(1000, 200, ""))
		default:
			t.Errorf("page_token %q", r.URL.Query().Get("page_token"))
		}
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil || len(got.Operations) != 1200 || got.Operations[0].Key != "op0" || got.Operations[1199].Key != "op1199" ||
		len(got.Tags) != 1 || got.ETag != `W/"12-aaa"` {
		t.Fatalf("got %d operations, %v", len(got.Operations), err)
	}
	if f.calls() != 3 || f.queries[0].Get("page_size") != "500" || f.queries[2].Get("page_token") != "op999" {
		t.Fatalf("calls: %v", f.uris)
	}
	if f.count() != 1 {
		t.Fatalf("one exchange for every page: %d", f.count())
	}
}

func TestServiceOperationsReadsAgainWhenTheListChanges(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		// The first reading sees tag a on page one and tag b on page two; the second sees b throughout.
		tag := `W/"12-b"`
		if n == 0 {
			tag = `W/"12-a"`
		}
		w.Header().Set("ETag", tag)
		if r.URL.Query().Get("page_token") == "" {
			writeJSON(w, http.StatusOK, opsPage(0, 2, "op1"))
			return
		}
		writeJSON(w, http.StatusOK, opsPage(2, 1, ""))
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil || len(got.Operations) != 3 || got.ETag != `W/"12-b"` || f.calls() != 4 {
		t.Fatalf("got %d operations, tag %q, %d calls, %v", len(got.Operations), got.ETag, f.calls(), err)
	}

	f, x, sub = newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("ETag", `W/"12-`+strconv.Itoa(n)+`"`)
		if r.URL.Query().Get("page_token") == "" {
			writeJSON(w, http.StatusOK, opsPage(0, 2, "op1"))
			return
		}
		writeJSON(w, http.StatusOK, opsPage(2, 1, ""))
	}
	if got, err := x.ServiceOperations(context.Background(), sub, "nadi"); err == nil || got.Operations != nil || f.calls() != 4 {
		t.Fatalf("a list that changes twice is an error: %d operations, %d calls, %v", len(got.Operations), f.calls(), err)
	}
}

func TestServiceOperationsReadsAgainOnInvalidPageToken(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("ETag", `W/"12-a"`)
		switch {
		case r.URL.Query().Get("page_token") == "":
			writeJSON(w, http.StatusOK, opsPage(0, 2, "op1"))
		case n == 1:
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "error_code": "invalid_page_token", "errors": []any{}})
		default:
			writeJSON(w, http.StatusOK, opsPage(2, 1, ""))
		}
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil || len(got.Operations) != 3 || f.calls() != 4 {
		t.Fatalf("got %d operations, %d calls, %v", len(got.Operations), f.calls(), err)
	}
}

func TestServiceOperationsFallsBackForANICEWithoutPaging(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Query().Has("page_size") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "error_code": "validation_failed",
				"errors": []any{map[string]any{"field": "page_size", "code": "unknown_field"}}})
			return
		}
		writeJSON(w, http.StatusOK, opsPage(0, 3, ""))
	}
	got, err := x.ServiceOperations(context.Background(), sub, "nadi")
	if err != nil || len(got.Operations) != 3 || f.calls() != 2 || f.uri(1) != "/api/v1/me/services/nadi/operations" {
		t.Fatalf("got %d operations, calls %v, %v", len(got.Operations), f.uris, err)
	}

	// Another validation error is returned as it is.
	f, x, sub = newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "error_code": "validation_failed",
			"errors": []any{map[string]any{"field": "service", "code": "invalid_value"}}})
	}
	var ae *APIError
	if _, err := x.ServiceOperations(context.Background(), sub, "nadi"); !errors.As(err, &ae) || ae.Status != 400 || f.calls() != 1 {
		t.Fatalf("other 400: %v, %d calls", err, f.calls())
	}
}

func TestServiceOperationsStopsAfterAHundredPages(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusOK, opsPage(n, 1, fmt.Sprintf("op%d", n)))
	}
	if got, err := x.ServiceOperations(context.Background(), sub, "nadi"); err == nil || got.Operations != nil || f.calls() != 100 {
		t.Fatalf("%d calls, %v", f.calls(), err)
	}
}

func TestServiceOperationsIfChanged(t *testing.T) {
	f, x, sub := newFakeAPI(t)
	f.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Query().Get("page_token") != "" && r.Header.Get("If-None-Match") != "" {
			t.Errorf("If-None-Match on a later page, call %d", n)
		}
		if r.Header.Get("If-None-Match") == `W/"12-a"` {
			w.Header().Set("ETag", `W/"12-a"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `W/"13-b"`)
		if r.URL.Query().Get("page_token") == "" {
			writeJSON(w, http.StatusOK, opsPage(0, 2, "op1"))
			return
		}
		writeJSON(w, http.StatusOK, opsPage(2, 1, ""))
	}
	got, changed, err := x.ServiceOperationsIfChanged(context.Background(), sub, "nadi", `W/"12-a"`)
	if err != nil || changed || !reflect.DeepEqual(got, ServiceOperations{}) || f.calls() != 1 {
		t.Fatalf("not modified: %+v %v %v", got, changed, err)
	}
	got, changed, err = x.ServiceOperationsIfChanged(context.Background(), sub, "nadi", `W/"11-old"`)
	if err != nil || !changed || len(got.Operations) != 3 || got.ETag != `W/"13-b"` {
		t.Fatalf("changed: %d operations, %v %v", len(got.Operations), changed, err)
	}
	n := f.calls()
	if _, changed, err := x.ServiceOperationsIfChanged(context.Background(), sub, "nadi", ""); err != nil || !changed {
		t.Fatalf("no etag: %v %v", changed, err)
	}
	if f.queries[n] == nil || f.calls() != n+2 {
		t.Fatalf("calls %v", f.uris[n:])
	}

	f2, x2, sub2 := newFakeAPI(t)
	f2.answer = func(w http.ResponseWriter, r *http.Request, n int) { t.Error("NICE called") }
	if _, _, err := x2.ServiceOperationsIfChanged(context.Background(), sub2, "", "tag"); err == nil || f2.count() != 0 {
		t.Fatalf("empty slug: %v", err)
	}
	f2.answer = func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "error_code": "not_found"})
	}
	var ae *APIError
	if _, _, err := x2.ServiceOperationsIfChanged(context.Background(), sub2, "nadi", "tag"); !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("404: %v", err)
	}
}
