package credentials

import (
	"strings"
	"testing"
)

func setEnv(t *testing.T, issuer, id, key string) {
	t.Setenv("NICE_ISSUER", issuer)
	t.Setenv("NICE_SA_ID", id)
	t.Setenv("NICE_SA_API_KEY", key)
}

func TestNewFromEnvBuildsAServiceAccountClient(t *testing.T) {
	f := newFakeNice(t, newClock())
	setEnv(t, f.srv.URL, "sa_integration", f.apiKey)
	c, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(bg, key("nadi")); err != nil {
		t.Fatal(err)
	}
	g := f.last()
	if g.Get("grant_type") != "client_credentials" || g.Get("client_id") != "sa_integration" || g.Get("client_secret") != f.apiKey {
		t.Fatalf("the grant uses the Service Account of the environment: %v", g)
	}
}

func TestAMissingVariableIsNamedWithoutCallingNICE(t *testing.T) {
	f := newFakeNice(t, newClock())
	const secret = "nice_sk_a.secret-value"
	for _, missing := range []string{"NICE_ISSUER", "NICE_SA_ID", "NICE_SA_API_KEY"} {
		t.Run(missing, func(t *testing.T) {
			setEnv(t, f.srv.URL, "sa_integration", secret)
			t.Setenv(missing, "")
			c, err := NewFromEnv()
			if err == nil || c != nil {
				t.Fatalf("an empty %s is an error", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Fatalf("the error names %s: %v", missing, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error does not show the API key: %v", err)
			}
		})
	}
	setEnv(t, "", "", "")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "NICE_ISSUER, NICE_SA_ID, NICE_SA_API_KEY") {
		t.Fatalf("every empty variable is named: %v", err)
	}
	if f.last() != nil {
		t.Fatal("NICE is not called")
	}
}

func TestTheApplicationSetsTheRestOfTheConfigFromEnv(t *testing.T) {
	f := newFakeNice(t, newClock())
	setEnv(t, f.srv.URL, "sa_integration", "nice_sk_a.wrong")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != KindServiceAccount || cfg.Issuer != f.srv.URL || cfg.ClientID != "sa_integration" {
		t.Fatalf("the Config holds the environment: %+v", cfg.Kind)
	}
	ended := make(chan string, 1)
	hc := f.srv.Client()
	cfg.HTTP = hc
	cfg.OnSessionEnded = func(subject string, err error) { ended <- subject }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.HTTP != hc {
		t.Fatal("the client uses the HTTP client of the application")
	}
	if _, err := c.Token(bg, key("nadi")); err == nil {
		t.Fatal("a wrong API key is refused")
	}
	select {
	case got := <-ended:
		if got != "sa_integration" {
			t.Fatalf("the session ended for %q", got)
		}
	default:
		t.Fatal("the handler of the application is told the key was refused")
	}
}
