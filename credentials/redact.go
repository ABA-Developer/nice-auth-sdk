package credentials

import (
	"fmt"
	"log/slog"
	"time"
)

const redactedMark = "[redacted]"

// redacted says whether a secret is set without showing it.
func redacted(secret string) string {
	if secret == "" {
		return `""`
	}
	return redactedMark
}

// String shows the Config without the secret; %v, %+v and %#v print it.
func (c Config) String() string {
	return fmt.Sprintf("credentials.Config{Issuer:%q ClientID:%q Kind:%d ClientSecret:%s}", c.Issuer, c.ClientID, c.Kind, redacted(c.ClientSecret))
}

// GoString is String, so %#v does not show the secret either.
func (c Config) GoString() string { return c.String() }

// LogValue keeps the secret out of structured logs.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("issuer", c.Issuer), slog.String("client_id", c.ClientID), slog.Int("kind", int(c.Kind)),
		slog.String("client_secret", redacted(c.ClientSecret)))
}

// String shows the ExchangeConfig without the secret.
func (c ExchangeConfig) String() string {
	return fmt.Sprintf("credentials.ExchangeConfig{Issuer:%q ClientID:%q ClientSecret:%s}", c.Issuer, c.ClientID, redacted(c.ClientSecret))
}

// GoString is String.
func (c ExchangeConfig) GoString() string { return c.String() }

// LogValue keeps the secret out of structured logs.
func (c ExchangeConfig) LogValue() slog.Value {
	return slog.GroupValue(slog.String("issuer", c.Issuer), slog.String("client_id", c.ClientID), slog.String("client_secret", redacted(c.ClientSecret)))
}

// String shows when the token was issued and expires, never the token. Its JSON form, which a Store keeps, is whole.
func (t Token) String() string {
	return fmt.Sprintf("credentials.Token{IssuedAt:%s ExpiresAt:%s Access:%s}", t.IssuedAt.Format(time.RFC3339), t.ExpiresAt.Format(time.RFC3339), redacted(t.Access))
}

// GoString is String.
func (t Token) GoString() string { return t.String() }

// LogValue keeps the token out of structured logs.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("issued_at", t.IssuedAt), slog.Time("expires_at", t.ExpiresAt), slog.String("access", redacted(t.Access)))
}

// String shows the Pending without the PKCE verifier. Its JSON form, which a PendingStore keeps, is whole.
func (p Pending) String() string {
	return fmt.Sprintf("credentials.Pending{Subject:%q RedirectURI:%q Audience:%q Project:%q Expires:%s Verifier:%s}",
		p.Subject, p.RedirectURI, p.Audience, p.Project, p.Expires.Format(time.RFC3339), redacted(p.Verifier))
}

// GoString is String.
func (p Pending) GoString() string { return p.String() }

// LogValue keeps the PKCE verifier out of structured logs.
func (p Pending) LogValue() slog.Value {
	return slog.GroupValue(slog.String("subject", p.Subject), slog.String("redirect_uri", p.RedirectURI), slog.String("audience", p.Audience),
		slog.String("project", p.Project), slog.Time("expires", p.Expires), slog.String("verifier", redacted(p.Verifier)))
}

// String names the client without its secret or its tokens.
func (c *Client) String() string {
	if c == nil {
		return "credentials.Client(nil)"
	}
	return "credentials.Client{" + c.cfg.String() + "}"
}

// GoString is String.
func (c *Client) GoString() string { return c.String() }

// String names the client without its secret or its tokens.
func (x *ExchangeClient) String() string {
	if x == nil {
		return "credentials.ExchangeClient(nil)"
	}
	return "credentials.ExchangeClient{" + x.cfg.String() + "}"
}

// GoString is String.
func (x *ExchangeClient) GoString() string { return x.String() }
