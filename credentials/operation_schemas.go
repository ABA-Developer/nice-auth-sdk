package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
)

// maxSchemaKeys is the number of keys NICE takes in one request for schemas.
const maxSchemaKeys = 20

// maxSchemasBody bounds the body of one request for schemas: 20 schemas of at most 64 KiB each, with room to spare.
const maxSchemasBody = 4 << 20

// OperationSchemas are the full schemas of operations of one service, as NICE reads them from its document.
type OperationSchemas struct {
	// Service is the slug of the service.
	Service string
	// Schemas are in the order the keys were given, each key once.
	Schemas []OperationSchema
	// Missing are the keys that are not active operations of the service or whose permission the user does not hold.
	Missing []string
}

// OperationSchema is the full schema of one operation. Both schemas are the JSON NICE sent, "{}" for an operation
// imported before NICE read schemas.
type OperationSchema struct {
	Key string
	// InputSchema is a JSON Schema object with the properties path, query, header and body; it can serve as the
	// input schema of a tool.
	InputSchema json.RawMessage
	// Responses maps each status of the document to its description, headers and JSON body schema in "schema".
	Responses json.RawMessage
	// Truncated is true when NICE cut the schema at 8 levels, at a recursive reference or at 64 KiB: a cut part keeps
	// its type alone.
	Truncated bool
}

type schemasBody struct {
	Service string `json:"service"`
	Schemas []struct {
		Key         string          `json:"key"`
		InputSchema json.RawMessage `json:"input_schema"`
		Responses   json.RawMessage `json:"responses"`
		Truncated   bool            `json:"truncated"`
	} `json:"schemas"`
	Missing []string `json:"missing"`
}

// OperationSchemas returns the schemas of the operations keys of the service slug for the user of subjectToken, read
// from GET /api/v1/me/services/{slug}/operation-schemas with the delegated token of the NICE API, as ServiceOperations.
// Any number of keys may be given: a repeated key is asked once, and the keys are sent 20 to a request, one request
// after the other. A failure of any request returns an error and no schemas.
//
// An empty slug, no key, or an empty key is refused before anything is exchanged or sent. A NICE that does not serve
// schemas answers 404, returned as an APIError. The other errors are those of Contexts.
func (x *ExchangeClient) OperationSchemas(ctx context.Context, subjectToken, slug string, keys []string) (OperationSchemas, error) {
	if slug == "" || slug == "." || slug == ".." {
		return OperationSchemas{}, errors.New("niceauth: the slug of the service is required")
	}
	if len(keys) == 0 {
		return OperationSchemas{}, errors.New("niceauth: at least one operation key is required")
	}
	var unique []string
	seen := map[string]bool{}
	for _, k := range keys {
		if k == "" {
			return OperationSchemas{}, errors.New("niceauth: an operation key is empty")
		}
		if !seen[k] {
			seen[k] = true
			unique = append(unique, k)
		}
	}
	const what = "GET /api/v1/me/services/{slug}/operation-schemas"
	out := OperationSchemas{Schemas: []OperationSchema{}, Missing: []string{}}
	missing := map[string]bool{}
	for start := 0; start < len(unique); start += maxSchemaKeys {
		chunk := unique[start:min(start+maxSchemaKeys, len(unique))]
		// Repeated keys rather than one comma separated value, so that a key holding a comma stays whole.
		target := "/api/v1/me/services/" + url.PathEscape(slug) + "/operation-schemas?" + url.Values{"keys": chunk}.Encode()
		var body schemasBody
		if _, err := x.niceGet(ctx, subjectToken, what, target, maxSchemasBody, nil, &body); err != nil {
			return OperationSchemas{}, err
		}
		out.Service = body.Service
		for _, s := range body.Schemas {
			out.Schemas = append(out.Schemas, OperationSchema{Key: s.Key, InputSchema: rawObject(s.InputSchema),
				Responses: rawObject(s.Responses), Truncated: s.Truncated})
		}
		for _, k := range body.Missing {
			if !missing[k] {
				missing[k] = true
				out.Missing = append(out.Missing, k)
			}
		}
	}
	return out, nil
}

// rawObject keeps the JSON NICE sent, and gives "{}" for an absent or null one.
func rawObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("{}")
	}
	return raw
}

// ResponseSchema gives the JSON Schema of the body of an answer with status: that of the exact status when the
// operation has one, else that of its range (such as 2XX), else that of default, else nil.
func (s OperationSchema) ResponseSchema(status int) json.RawMessage {
	var responses map[string]struct {
		Schema json.RawMessage `json:"schema"`
	}
	if json.Unmarshal(s.Responses, &responses) != nil {
		return nil
	}
	code := strconv.Itoa(status)
	candidates := []string{code}
	if len(code) == 3 {
		candidates = append(candidates, code[:1]+"XX", code[:1]+"xx")
	}
	candidates = append(candidates, "default")
	for _, c := range candidates {
		if r, ok := responses[c]; ok {
			if len(r.Schema) == 0 || string(r.Schema) == "null" {
				return nil
			}
			return r.Schema
		}
	}
	return nil
}
