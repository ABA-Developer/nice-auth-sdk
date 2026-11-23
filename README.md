# nice-auth-sdk

The Go SDK for NICE. It has two packages, one for each side of an integration:

| You write | Package |
|---|---|
| a caller that gets tokens and then calls services (Service Account, backend, exchange) | `credentials` |
| a service that receives and checks NICE tokens | `verify` |

The two packages do not import each other. `verify` needs only the standard library and `go-jose`, so a service that only verifies does not carry the caller side.

## Install

```bash
go get github.com/ABA-Developer/nice-auth-sdk
```

It needs Go 1.24 or later.

## Runnable examples

Each folder in [`examples/`](examples) is one `main` program for one role. Its settings come from the environment and are listed in the comment at the top of `main.go`.

| Example | Role | What it shows |
|---|---|---|
| [`examples/service_account`](examples/service_account/main.go) | a machine caller | `ConfigFromEnv`, `HTTPClient`, reading errors |
| [`examples/service`](examples/service/main.go) | a service that receives tokens | `Middleware`, `Require`, `Sensitive`, the feed, the permission resolver, tenants |
| [`examples/exchange`](examples/exchange/main.go) | a backend that calls another service on behalf of a user | `NewExchange`, `DoAs` |
| [`examples/connect`](examples/connect/main.go) | a web backend that signs a user in and keeps the refresh token | `AuthorizeURL`, `HandleCallback`, `Do`, `Disconnect` |

```bash
export NICE_ISSUER=https://auth.example.com NICE_SA_ID=sa_... NICE_SA_API_KEY=...
SERVICE_SLUG=nadi SERVICE_URL=https://nadi.example.com go run ./examples/service_account
```

The snippets below summarize the first three.

## A machine caller (Service Account)

A Service Account proves its API key to NICE (`client_credentials`), then calls a service with the token it gets. The SDK keeps the token in memory, renews it in the background, and sends a request once more when the service answers 401 `token_stale`.

```go
import "github.com/ABA-Developer/nice-auth-sdk/credentials"

c, err := credentials.NewFromEnv() // NICE_ISSUER, NICE_SA_ID, NICE_SA_API_KEY
if err != nil {
	log.Fatal(err)
}
go c.Run(ctx) // renew the tokens in use

hc, err := c.HTTPClient(credentials.Key{Audience: "nadi"}, "https://nadi.example.com")
if err != nil {
	log.Fatal(err)
}
resp, err := hc.Get("https://nadi.example.com/devices")
```

The client of `HTTPClient` sends the token to the named service address only. A request or a redirect to another host fails with `ErrForeignHost`.

## A service that receives tokens

A service verifies the token itself, without asking NICE on each request: the signature (RS256, JWKS), `iss`, `aud`, the lifetime, and the access changes from the feed.

```go
import "github.com/ABA-Developer/nice-auth-sdk/verify"

v, err := verify.New(verify.Config{
	Issuer:   "https://auth.example.com",
	Service:  "nadi",                    // the slug of the service; a token must be for it alone
	JWKSFile: "/var/lib/nadi/jwks.json", // the service still verifies after a restart while NICE is down
	Checker:  verify.NewHTTPChecker("https://auth.example.com", apiKey),
	Resolver: verify.NewHTTPResolver("https://auth.example.com", apiKey),
})
if err != nil {
	log.Fatal(err)
}
go v.Run(ctx)
if err := v.StartFeed(ctx, verify.FeedConfig{APIKey: apiKey}); err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("GET /devices", v.Require("nadi.devices.read")(http.HandlerFunc(list)))
mux.Handle("DELETE /devices/{id}", v.Require("nadi.devices.delete", verify.Sensitive())(http.HandlerFunc(remove)))
log.Fatal(http.ListenAndServe(":8081", v.Middleware(mux)))
```

A handler reads who is calling from the context:

```go
func list(w http.ResponseWriter, r *http.Request) {
	claims, _ := verify.FromContext(r.Context())       // sub, organization, project, permissions
	tenant, _ := verify.TenantFromContext(r.Context()) // the tenant of the organization in the token, never from client input
	// ...
}
```

- `Require` checks the permission in the `perms` claim.
- `Sensitive()` adds an online check with NICE; when NICE does not answer, the request is refused with 503.
- `StartFeed` makes a token issued before an access change refused with `token_stale`.
- `Resolver` gets the permissions of a token that carries `perms_ref` instead of `perms`. NICE issues one when a principal holds so many permissions that they would not fit in a header. The verifier asks NICE once for each permission list and keeps it, so a handler reads `claims.Permissions` and `Require` works the same on every token. Without a resolver such a token is refused with 503, so set it in every service. It uses the API key of the access check and the feed.

The full contract is in [docs/token-verification.md](docs/token-verification.md).

## A backend that calls another service on behalf of a user

The backend exchanges the user token that came with the request (RFC 8693) for a token for the target service. The backend holds no refresh token.

```go
x, err := credentials.NewExchange(credentials.ExchangeConfig{
	Issuer: "https://auth.example.com", ClientID: clientID, ClientSecret: clientSecret,
})

// userToken: the token of the request, which the backend has verified
req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://inventaris.example.com/items", nil)
resp, err := x.DoAs(ctx, userToken, credentials.Key{Audience: "inventaris"}, req)
```

## Reading errors

```go
var grant *credentials.GrantError
switch {
case errors.As(err, &grant) && grant.Permanent: // NICE refused for good: replace the key or ask the user to sign in again
case errors.As(err, &grant):                    // NICE refused this request only (e.g. access_denied)
case credentials.IsTemporary(err):              // NICE cannot be reached: try again later
case errors.Is(err, credentials.ErrForeignHost): // a request to another host than the service of this client
}
```

## Security rules

- **HTTPS.** The address of NICE and the address of a service must be `https`. `http` is accepted for loopback (`localhost`, `127.0.0.0/8`, `::1`), so a local stack needs no setting. For a network where TLS ends somewhere else, set `AllowInsecureHTTP` in the `Config`; no environment variable does it.
- **No redirect to NICE.** The calls of the SDK to NICE follow no redirect, so a secret is never sent to where a redirect points.
- **Secrets are not printed.** `Config`, `ExchangeConfig`, `FeedConfig`, and `Token` hide their secret when printed or logged. The JSON form of a `Token` stays whole because a `Store` keeps it that way: do not log a struct that holds a `Token` through a JSON encoder.
- **Refresh tokens.** `FileStore` keeps them as files only their owner can read, not encrypted. In production, use a `Store` of your own that encrypts them.

How to report a vulnerability is in [SECURITY.md](SECURITY.md).

## Other languages

An implementation in another language follows [docs/token-verification.md](docs/token-verification.md) and must give the same answers for every vector in `verify/testdata/vectors.json`.

## Developing

```bash
go vet ./...
go test ./... -count=1 -race
```

The tests need no running NICE. `layout_test.go` keeps `verify` and `credentials` from importing each other.

## License

Apache License 2.0. See [LICENSE](LICENSE).
