package credentials

import "testing"

func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		name, schema, body, want string
	}{
		{"array of objects",
			`{"type":"object","properties":{"devices":{"type":"array","items":{"type":"object","properties":{"api_key":{"type":"string","x-secret":true},"id":{"type":"string"}}}}}}`,
			`{"total":2,"devices":[{"id":"a","api_key":"k1","extra":1},{"api_key":"k2","id":"b"}]}`,
			`{"total":2,"devices":[{"id":"a","extra":1},{"id":"b"}]}`},
		{"allOf member",
			`{"allOf":[{"type":"object","properties":{"name":{"type":"string"}}},{"properties":{"token":{"x-secret":true}}}]}`,
			`{"name":"n","token":"t"}`, `{"name":"n"}`},
		{"oneOf member",
			`{"oneOf":[{"properties":{"password":{"type":"string","x-secret":true}}},{"properties":{"code":{"type":"string"}}}]}`,
			`{"password":"p","code":"c"}`, `{"code":"c"}`},
		{"additionalProperties",
			`{"type":"object","properties":{"id":{"type":"string"}},"additionalProperties":{"type":"object","properties":{"secret":{"x-secret":true},"v":{}}}}`,
			`{"id":"1","env":{"secret":"s","v":2}}`, `{"id":"1","env":{"v":2}}`},
		{"additionalProperties secret itself",
			`{"type":"object","additionalProperties":{"type":"string","x-secret":true}}`,
			`{"a":"1","b":"2"}`, `{}`},
		{"empty schema", `{}`, `{"api_key":"k"}`, `{"api_key":"k"}`},
		{"no schema", ``, `{"api_key":"k"}`, `{"api_key":"k"}`},
		{"order and numbers",
			`{"properties":{"s":{"x-secret":true}}}`,
			`{"z":12345678901234567890,"s":"x","a":1.50,"m":[1e3,null,true,"é"]}`,
			`{"z":12345678901234567890,"a":1.50,"m":[1e3,null,true,"é"]}`},
		{"top-level array",
			`{"type":"array","items":{"properties":{"k":{"x-secret":true}}}}`,
			`[{"k":1,"v":2}]`, `[{"v":2}]`},
	}
	for _, c := range cases {
		got, err := RedactSecrets([]byte(c.schema), []byte(c.body))
		if err != nil || string(got) != c.want {
			t.Fatalf("%s: got %s, %v; want %s", c.name, got, err, c.want)
		}
	}
}

func TestRedactSecretsRefusesABodyThatIsNotJSON(t *testing.T) {
	for _, body := range []string{"plain text", `{"a":1} {"b":2}`, `{"a":`, ""} {
		if got, err := RedactSecrets([]byte(`{}`), []byte(body)); err == nil || got != nil {
			t.Fatalf("%q: got %s, %v", body, got, err)
		}
	}
	if got, err := RedactSecrets([]byte(`{`), []byte(`{}`)); err == nil || got != nil {
		t.Fatalf("a schema that is not JSON: %s, %v", got, err)
	}
}
