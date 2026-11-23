package verify

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// maxSkew is the largest clock skew the contract allows.
const maxSkew = 60 * time.Second

// Config configures a Verifier.
type Config struct {
	// Issuer is the exact iss of NICE tokens, e.g. https://auth.example.com.
	Issuer string
	// Service is the slug of this service; a token must be for it alone (aud).
	Service string
	// JWKSURL defaults to Issuer + "/oauth/keys".
	JWKSURL string
	// JWKSFile keeps a copy of the JWKS on disk, read at start, so a service that
	// restarts while NICE is down still verifies. Strongly recommended.
	JWKSFile string
	// StaticJWKS, when set, is the key set and nothing is fetched (tests and vectors).
	StaticJWKS []byte
	// HTTP fetches the JWKS; default http.DefaultClient. The fetch goes through a copy that follows no redirect.
	HTTP *http.Client
	// AllowInsecureHTTP accepts a plain http address of NICE that is not loopback (the JWKS, the feed, the
	// access check, the permission resolution), for a network where TLS ends somewhere else. Without it such an
	// address is refused: the keys could be replaced on the way and the API key would cross the network in the
	// clear. Loopback (localhost, 127.0.0.0/8, ::1) needs no option.
	AllowInsecureHTTP bool
	// Skew is the allowed clock skew, at most 60 seconds; default 60 seconds.
	Skew time.Duration
	// JWKSRefresh is how often the JWKS is refreshed by Run; default 10 minutes.
	JWKSRefresh time.Duration
	// UnknownKeyRefresh is the least time between refreshes caused by an unknown kid; default 1 minute.
	UnknownKeyRefresh time.Duration
	// TokenTTL is the lifetime of a NICE token, which bounds how long access changes are remembered; default 30
	// minutes. It must equal NICE_ACCESS_TOKEN_TTL of NICE: a token that lives longer than TokenTTL plus the skew
	// is refused with token_lifetime_exceeded, since a change that revoked it would be forgotten before it expires.
	TokenTTL time.Duration
	// Tenants decides how an organization becomes known; nil accepts every organization.
	Tenants TenantResolver
	// Checker answers online access checks for sensitive operations; nil refuses them with 503.
	Checker AccessChecker
	// Resolver gets the permissions of a token that carries perms_ref instead of perms; nil refuses such a token
	// with 503. NICE issues one when the permissions would make the token too large for a header.
	Resolver PermissionResolver
	// Observer receives rejections and feed state; nil ignores them.
	Observer Observer
	// Log defaults to slog.Default().
	Log *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Verifier verifies NICE access tokens for one service.
type Verifier struct {
	cfg  Config
	keys *keySet
	deny *denySet
	obs  Observer
	feed *feedState
	// lifetimeWarned is the unix nanoseconds of the last warning about a token that outlives TokenTTL.
	lifetimeWarned atomic.Int64
}

// New builds a Verifier. It reads the copy of the JWKS on disk and then asks NICE;
// when neither gives a key it still returns the Verifier, which answers 503 until
// Run (or a request with a new kid) fetches the keys.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Service == "" {
		return nil, errConfig("Issuer and Service are required")
	}
	if cfg.Skew <= 0 || cfg.Skew > maxSkew {
		cfg.Skew = maxSkew
	}
	if cfg.JWKSRefresh <= 0 {
		cfg.JWKSRefresh = 10 * time.Minute
	}
	if cfg.UnknownKeyRefresh <= 0 {
		cfg.UnknownKeyRefresh = time.Minute
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 30 * time.Minute
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = strings.TrimRight(cfg.Issuer, "/") + "/oauth/keys"
	}
	if cfg.HTTP == nil {
		cfg.HTTP = http.DefaultClient
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.StaticJWKS) == 0 {
		if err := checkURL("JWKSURL", cfg.JWKSURL, cfg.AllowInsecureHTTP); err != nil {
			return nil, err
		}
	}
	for _, caller := range []any{cfg.Checker, cfg.Resolver} {
		if c, ok := caller.(interface {
			validate(allowInsecure bool) error
		}); ok {
			if err := c.validate(cfg.AllowInsecureHTTP); err != nil {
				return nil, err
			}
		}
	}
	v := &Verifier{cfg: cfg, deny: newDenySet(cfg.TokenTTL + cfg.Skew), obs: cfg.Observer}
	if v.obs == nil {
		v.obs = noObserver{}
	}
	v.keys = &keySet{url: cfg.JWKSURL, file: cfg.JWKSFile, client: noRedirect(cfg.HTTP), log: cfg.Log, now: cfg.Now, minUnknown: cfg.UnknownKeyRefresh,
		static: len(cfg.StaticJWKS) > 0}
	switch {
	case len(cfg.StaticJWKS) > 0:
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(cfg.StaticJWKS, &set); err != nil {
			return nil, errConfig("StaticJWKS is not a JWKS: " + err.Error())
		}
		v.keys.load(set)
	default:
		v.keys.readFile()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := v.keys.refresh(ctx); err != nil {
			cfg.Log.Warn("niceauth: JWKS not fetched at start", slog.String("error", err.Error()), slog.Bool("have_copy", !v.keys.empty()))
		}
	}
	return v, nil
}

type errConfig string

func (e errConfig) Error() string { return "niceauth: " + string(e) }

// Run refreshes the JWKS every JWKSRefresh until ctx is done.
func (v *Verifier) Run(ctx context.Context) {
	t := time.NewTicker(v.cfg.JWKSRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := v.keys.refresh(ctx); err != nil {
				v.cfg.Log.Warn("niceauth: JWKS refresh failed, keeping the last keys", slog.String("error", err.Error()))
			}
		}
	}
}

// warnLifetime logs a token that lives longer than TokenTTL allows, at most once a minute: it is a configuration
// error that refuses every token, not an attack worth a line per request.
func (v *Verifier) warnLifetime(now time.Time, life int64, noIAT bool) {
	last := v.lifetimeWarned.Load()
	if last != 0 && now.UnixNano()-last < int64(time.Minute) {
		return
	}
	if !v.lifetimeWarned.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	if noIAT {
		v.cfg.Log.Warn("niceauth: a token without iat was refused; its lifetime cannot be checked against TokenTTL")
		return
	}
	v.cfg.Log.Warn("niceauth: a token lives longer than Config.TokenTTL allows and was refused; set TokenTTL to NICE_ACCESS_TOKEN_TTL of NICE",
		slog.Duration("token_lifetime", time.Duration(life)*time.Second), slog.Duration("token_ttl", v.cfg.TokenTTL))
}

func (v *Verifier) reject(e *Error) *Error {
	v.obs.Rejected(e.Description)
	return e
}

// Verify checks token: algorithm, signature, issuer, audience, expiry and the
// access changes received from the feed. It does not check permissions.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		reason := ReasonMalformed
		if parsed, perr := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.HS256, jose.HS384, jose.HS512, jose.EdDSA}); perr == nil && len(parsed.Signatures) > 0 {
			reason = ReasonAlgorithm
		} else if looksSigned(token) {
			reason = ReasonAlgorithm
		}
		return nil, v.reject(invalid(reason))
	}
	if len(jws.Signatures) != 1 {
		return nil, v.reject(invalid(ReasonMalformed))
	}
	kid := jws.Signatures[0].Header.KeyID
	key, ok := v.keys.lookup(kid)
	if !ok {
		if v.keys.empty() {
			if err := v.keys.refresh(ctx); err != nil {
				return nil, v.reject(unavailable("temporarily_unavailable", ReasonKeysDown))
			}
		}
		if key, ok = v.keys.unknown(ctx, kid); !ok {
			if v.keys.empty() {
				return nil, v.reject(unavailable("temporarily_unavailable", ReasonKeysDown))
			}
			return nil, v.reject(invalid(ReasonUnknownKey))
		}
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, v.reject(invalid(ReasonSignature))
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, v.reject(invalid(ReasonMalformed))
	}
	// NICE never issues both: a token that says its permissions twice could say two different things.
	if c.PermsRef != "" && c.Permissions != nil {
		return nil, v.reject(invalid(ReasonMalformed))
	}
	if c.Issuer != v.cfg.Issuer {
		return nil, v.reject(invalid(ReasonIssuer))
	}
	if len(c.Audience) != 1 || c.Audience[0] != v.cfg.Service {
		return nil, v.reject(invalid(ReasonAudience))
	}
	now := v.cfg.Now()
	if c.ExpiresAt == 0 || now.After(time.Unix(c.ExpiresAt, 0).Add(v.cfg.Skew)) {
		return nil, v.reject(invalid(ReasonExpired))
	}
	if c.NotBefore != 0 && now.Add(v.cfg.Skew).Before(time.Unix(c.NotBefore, 0)) {
		return nil, v.reject(invalid(ReasonNotYetValid))
	}
	// The deny-set keeps a change for TokenTTL plus the skew. A token that lives longer would outlive the change
	// that revoked it, so it is refused: the lifetime of NICE (NICE_ACCESS_TOKEN_TTL) must not exceed TokenTTL.
	if life := c.ExpiresAt - c.IssuedAt; c.IssuedAt == 0 || life > int64((v.cfg.TokenTTL+v.cfg.Skew)/time.Second) {
		v.warnLifetime(now, life, c.IssuedAt == 0)
		return nil, v.reject(invalid(ReasonLifetime))
	}
	keys := []denyKey{{key: "p:" + c.Subject + "|" + c.OrgID}, {key: "o:" + c.OrgID}}
	if c.ProjectID != "" {
		keys = append(keys, denyKey{key: "j:" + c.ProjectID})
	}
	if c.ActAs != "" {
		// The right of an operator is decided in the organization nice_act_as names, so a change there ends the token.
		keys = append(keys, denyKey{key: "p:" + c.Subject + "|" + c.ActAs, actAs: true})
	}
	if v.deny.stale(tokenVersion{iat: c.IssuedAt, org: c.OrgID, pv: c.PolicyVersion, hasPV: c.hasPV}, keys...) {
		return nil, v.reject(invalid(ReasonStale))
	}
	return &c, nil
}

// looksSigned reports whether token has three dot-separated parts whose header
// names an algorithm: such a token was refused for its algorithm, not for its shape.
func looksSigned(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	return decodeAlg(parts[0]) != ""
}

func decodeAlg(header string) string {
	b, err := base64RawURL(header)
	if err != nil {
		return ""
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(b, &h) != nil {
		return ""
	}
	return h.Alg
}
