package credentials

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

// shown is every way a value ends up in a log: the fmt verbs and a structured logger.
func shown(v any) string {
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("value", slog.Any("v", v))
	slog.New(slog.NewTextHandler(&b, nil)).Info("value", slog.Any("v", v))
	return fmt.Sprintf("%v|%+v|%#v|%s|", v, v, v, v) + b.String()
}

func TestSecretsAreNotPrinted(t *testing.T) {
	const secret = "nice_sk_a.very-secret-value"
	clk := newClock()
	cfg := Config{Issuer: "https://auth.example.com", ClientID: "sa_integration", ClientSecret: secret, Kind: KindServiceAccount}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	xcfg := ExchangeConfig{Issuer: "https://auth.example.com", ClientID: "naia-backend", ClientSecret: secret}
	x, err := NewExchange(xcfg)
	if err != nil {
		t.Fatal(err)
	}
	tok := Token{Access: secret, IssuedAt: clk.now(), ExpiresAt: clk.now().Add(30 * time.Minute)}
	pend := Pending{Verifier: secret, Subject: "user-1", RedirectURI: "https://app.example.com/cb", Expires: clk.now()}
	type holder struct {
		Config   Config
		Exchange ExchangeConfig
	}
	for name, v := range map[string]any{
		"Config": cfg, "*Config": &cfg, "ExchangeConfig": xcfg, "*ExchangeConfig": &xcfg, "Token": tok, "*Token": &tok,
		"Pending": pend, "*Client": c, "*ExchangeClient": x, "a struct that holds the configs": holder{cfg, xcfg},
	} {
		if out := shown(v); strings.Contains(out, secret) {
			t.Errorf("%s shows the secret: %s", name, out)
		}
	}
	// A JSON encoder never sees the secret of a config, whatever holds it. (A Token keeps its JSON form for the Store.)
	for _, typ := range []reflect.Type{reflect.TypeFor[Config](), reflect.TypeFor[ExchangeConfig]()} {
		if f, _ := typ.FieldByName("ClientSecret"); f.Tag.Get("json") != "-" {
			t.Errorf("%s.ClientSecret must be left out of the JSON form", typ)
		}
	}
	// Inside another struct, the fmt verbs still go through String.
	type tokens struct{ Token Token }
	if out := fmt.Sprintf("%v|%+v|%#v", tokens{tok}, tokens{tok}, tokens{tok}); strings.Contains(out, secret) {
		t.Errorf("a struct that holds a Token shows it: %s", out)
	}
	for name, v := range map[string]any{"Config": cfg, "ExchangeConfig": xcfg, "*Client": c, "*ExchangeClient": x} {
		if out := shown(v); !strings.Contains(out, "https://auth.example.com") || !strings.Contains(out, "ClientID") {
			t.Errorf("%s still names the issuer and the client: %s", name, out)
		}
	}
	if out := shown(tok); !strings.Contains(out, "ExpiresAt") {
		t.Errorf("a Token still shows when it expires: %s", out)
	}
	if out := shown(Config{Issuer: "https://auth.example.com", ClientID: "console"}); strings.Contains(out, redactedMark) {
		t.Errorf("an empty secret is shown as empty: %s", out)
	}
}

func TestTheFileStoreStillKeepsWholeTokens(t *testing.T) {
	clk := newClock()
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k := Key{Subject: "user-1", Audience: "nadi", Project: "prj_a"}
	tok := Token{Access: "the.access.token", IssuedAt: clk.now(), ExpiresAt: clk.now().Add(30 * time.Minute)}
	if err := s.SaveToken(bg, k, tok); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.LoadToken(bg, k); err != nil || !ok || got.Access != tok.Access || !got.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Fatalf("the token read is the token saved: %v %v %v", got, ok, err)
	}
	p := Pending{Verifier: "pkce-verifier", Subject: "user-1", Session: "s1", RedirectURI: "https://app.example.com/cb", Expires: clk.now()}
	if err := s.SavePending(bg, "state-1", p); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.TakePending(bg, "state-1"); err != nil || !ok || got.Verifier != p.Verifier {
		t.Fatalf("the pending connection read is the one saved: %v %v %v", got, ok, err)
	}
}
