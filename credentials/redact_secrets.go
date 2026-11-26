package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RedactSecrets removes from the JSON body every object property whose schema carries x-secret: true, following
// schema into properties, array items, the members of allOf, oneOf and anyOf, and additionalProperties. schema is the
// JSON Schema of the body, such as OperationSchema.ResponseSchema gives. Properties the schema does not describe, and
// parts under a cut schema, are left as they are; the order of the other properties and the text of their numbers
// do not change. A body that is not JSON returns an error and no body.
func RedactSecrets(schema json.RawMessage, body []byte) ([]byte, error) {
	var root any
	if len(bytes.TrimSpace(schema)) > 0 {
		if err := json.Unmarshal(schema, &root); err != nil {
			return nil, fmt.Errorf("niceauth: the schema is not JSON: %w", err)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	v, err := readValue(dec)
	if err != nil {
		return nil, errors.New("niceauth: the body is not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("niceauth: the body is not one JSON value")
	}
	var out bytes.Buffer
	writeValue(&out, redact(v, schemaList(root)))
	return out.Bytes(), nil
}

// orderedObject keeps the properties of a JSON object in the order of the body.
type orderedObject struct {
	keys []string
	vals []any
}

func readValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &orderedObject{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := readValue(dec)
				if err != nil {
					return nil, err
				}
				o.keys = append(o.keys, k.(string))
				o.vals = append(o.vals, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := readValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return a, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return tok, nil
	}
}

func writeValue(w *bytes.Buffer, v any) {
	switch t := v.(type) {
	case *orderedObject:
		w.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				w.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			w.Write(kb)
			w.WriteByte(':')
			writeValue(w, t.vals[i])
		}
		w.WriteByte('}')
	case []any:
		w.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				w.WriteByte(',')
			}
			writeValue(w, x)
		}
		w.WriteByte(']')
	case json.Number:
		w.WriteString(t.String())
	default:
		b, _ := json.Marshal(t)
		w.Write(b)
	}
}

// schemaList gives s and, recursively, the members of its allOf, oneOf and anyOf: every schema that applies to one
// value.
func schemaList(s any) []map[string]any {
	m, ok := s.(map[string]any)
	if !ok {
		return nil
	}
	out := []map[string]any{m}
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		if members, ok := m[k].([]any); ok {
			for _, x := range members {
				out = append(out, schemaList(x)...)
			}
		}
	}
	return out
}

func redact(v any, schemas []map[string]any) any {
	if len(schemas) == 0 {
		return v
	}
	switch t := v.(type) {
	case *orderedObject:
		out := &orderedObject{}
		for i, k := range t.keys {
			var child []map[string]any
			secret, described := false, false
			for _, s := range schemas {
				props, _ := s["properties"].(map[string]any)
				if p, ok := props[k]; ok {
					described = true
					if pm, ok := p.(map[string]any); ok && pm["x-secret"] == true {
						secret = true
					}
					child = append(child, schemaList(p)...)
				}
			}
			if !described {
				for _, s := range schemas {
					child = append(child, schemaList(s["additionalProperties"])...)
				}
				for _, s := range child {
					if s["x-secret"] == true {
						secret = true
					}
				}
			}
			if secret {
				continue
			}
			out.keys = append(out.keys, k)
			out.vals = append(out.vals, redact(t.vals[i], child))
		}
		return out
	case []any:
		var items []map[string]any
		for _, s := range schemas {
			items = append(items, schemaList(s["items"])...)
		}
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redact(x, items)
		}
		return out
	}
	return v
}
