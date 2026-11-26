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
| [`examples/exchange`](examples/exchange/main.go) | a backend that calls another service on behalf of a user | `NewExchange`, `DoAs`, `Services`, `ServiceOperations(IfChanged)`, `OperationSchemas`, `RedactSecrets`, `CallOperation` |
| [`examples/connect`](examples/connect/main.go) | a web backend that signs a user in and keeps the refresh token | `AuthorizeURL`, `HandleCallback`, `SignInToken`, `Contexts`, `Do`, `Disconnect`, `PromptSelectAccount`, `EndSessionURL` |

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
	Checker:  verify.NewHTTPChecker("https://auth.example.com"),
	Resolver: verify.NewHTTPResolver("https://auth.example.com"),
})
if err != nil {
	log.Fatal(err)
}
go v.Run(ctx)
if err := v.StartFeed(ctx, verify.FeedConfig{}); err != nil {
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
- `Resolver` gets the permissions of a token that carries `perms_ref` instead of `perms`. NICE issues one when a principal holds so many permissions that they would not fit in a header. The verifier asks NICE once for each permission list and keeps it, so a handler reads `claims.Permissions` and `Require` works the same on every token. Without a resolver such a token is refused with 503, so set it in every service.

The service holds no credential of NICE. The feed needs none and names what changed only by hashed keys (`verify.FeedKey`). The online check and the resolution send the token of the request being handled as their `Authorization: Bearer`, and NICE reads the caller from it. They work only with the `Claims` that `Verify` returned.

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

## Choosing an organization and a project

A token for a service names one organization and one project. Before the user has picked them, the backend lists where the user may work with `ExchangeClient.Contexts`. It exchanges a user token for a delegated token of the NICE API (`Key{Audience: "nice"}`), reads every page of `GET /api/v1/me/contexts`, and returns the organizations in the order NICE gives them, each with its projects and the services the user may use in each.

A web backend that keeps the refresh token (`KindBFF`) does it right after the sign-in. The `ExchangeClient` uses the same service client as the `Client`:

```go
conn, err := c.HandleCallback(ctx, sessionID, r.URL.Query())
// ...
signIn, err := c.SignInToken(ctx, subject) // a token for the client itself, before any project is known
contexts, err := x.Contexts(ctx, signIn.Access)
for _, o := range contexts.Organizations {
	// o.ID, o.Name, o.ActAs (a platform operator acting as this organization), o.ProjectsTruncated
	for _, p := range o.Projects {
		// p.ID, p.Name, p.Services: the slugs of the services the user may use in p
	}
}

// The user picks an organization and a project; keep them in the session and name them on every call.
resp, err := c.Do(ctx, credentials.Key{Subject: subject, Org: org, Audience: "navi", Project: project}, req)
```

The backend of a service passes the token of the request it serves, after verifying it:

```go
contexts, err := x.Contexts(ctx, userToken)
```

- **`Project` is required** for the token of a service: NICE refuses it without a project (`invalid_scope`). Offer the projects whose `Services` hold the slug of the service.
- **A SPA (public client) cannot use `Contexts`.** The exchange needs the secret of a confidential service client. A SPA picks the context by hand or asks a backend (BFF) that holds the secret.

[`examples/connect`](examples/connect/main.go) shows the whole flow with a picker.

## Finding services and operations for an agent

An agent, or any backend that works on behalf of a user, does not have to list its tools by hand. NICE tells it which other services the user may call, in which projects, and which operations of each service the user holds the permission of. Three functions of `ExchangeClient` cover the flow:

| Step | Function | Subject token | What NICE is asked |
|---|---|---|---|
| 1 | `Client.SignInToken` | | a refresh with the base scopes: a token for the client itself |
| 2 | `Services` | the sign-in token | `GET /api/v1/me/services`, every page |
| 3 | `ServiceOperations` | the sign-in token | `GET /api/v1/me/services/{slug}/operations`, every page |
| 3b | `OperationSchemas` | the sign-in token | `GET /api/v1/me/services/{slug}/operation-schemas`, 20 keys a request |
| 4 | `CallOperation` | a token of the user for the service of the client | one exchange per organization, project and service, then the call to the service |

```go
signIn, err := c.SignInToken(ctx, subject)

// Once per session: where the user may call which service.
services, err := x.Services(ctx, signIn.Access)
for _, o := range services.Organizations {
	for _, p := range o.Projects {
		// p.Services: the slugs of the services the user may call in p, e.g. ["nadi"]
	}
}

// When a prompt needs nadi. The operations of a service are the same in every project.
ops, err := x.ServiceOperations(ctx, signIn.Access, "nadi")
for _, op := range ops.Operations {
	// op.Key, op.Method, op.Path, op.Summary, op.Description, op.Permission, op.Sensitive, op.Headers, op.RequestFields
	// each field: Location, Name, Required, Type, Description, Format, Enum, EnumTruncated
}

// Before the next prompt: read the list again only when it changed. Keep ops and ops.ETag between prompts.
fresh, changed, err := x.ServiceOperationsIfChanged(ctx, signIn.Access, "nadi", ops.ETag)
if changed {
	ops = fresh
}

// When the model picks a tool: its full input and response schemas.
schemas, err := x.OperationSchemas(ctx, signIn.Access, "nadi", []string{"listDevices", "getDevice"})
// schemas.Schemas[i].InputSchema is a JSON Schema object (path, query, header, body), usable as a tool input schema.

// A call needs a token of the user for the service of the client (here naia), in a project where naia is active:
// one of the projects Contexts lists. One such token serves every organization and project of the map.
naia, err := c.Token(ctx, credentials.Key{Subject: subject, Audience: "naia", Project: naiaProject})

resp, err := x.CallOperation(ctx, naia.Access, credentials.OperationCall{
	Service:    nadi,      // from services.Services
	Operation:  getDevice, // from ops.Operations
	Org:        org,     // an organization of the map
	Project:    project, // one of its projects that lists nadi
	PathParams: map[string]string{"id": "dev 01"}, // GET <endpoint><base path>/devices/dev%2001
})
```

The backend of a service passes the verified token of the request as the subject token of all three.

- **Steps 2 and 3 share one exchange** with `Contexts`: the delegated token of the NICE API is kept per subject token. Neither exchanges a token for a service, so listing tools costs that one exchange and none, with its `token.exchange` audit record, per service or project. The SDK keeps no map and no operations: read them again to see a change.
- **The answers come from the roles of the user at that moment**, not from the `perms` claim of a token. A user whose tokens carry `perms_ref` gets the same map.
- **The sign-in token cannot be the subject of `CallOperation`.** NICE exchanges it for the NICE API only, and answers `invalid_grant` for a service. At least one project must therefore have the service of the client active; the service need not be active in the projects of the map.
- **`ProjectsTruncated`** is true when an organization has more projects than NICE lists (100). Treat it as a warning: an answer over "every location" of that organization is not complete. `ServiceOperations` is not affected by that limit.
- **A service the user may not call is `404 not_found`** from `ServiceOperations`, as an `APIError`, whatever the reason.
- **Path parameters.** `CallOperation` replaces every `{name}` of the path with its value as one escaped segment. Before anything is exchanged it refuses, with an error that wraps `ErrInvalidOperationCall` and names the parameter, a `{name}` without a value, a value for a name the path does not hold, and a value that is empty, is `.` or `..`, or holds a slash, a backslash or a control character. These values often come from a model, and a path that moves would call another operation with the same token.
- **Headers and body.** The headers of `Operation.Headers` replace a header of the same name in `Header`, and `Authorization` is always the exchanged token. `Body` is sent as it is, as `application/json` when no content type is named.
- **The answer of the service is returned as it is**, also a `403` or a `503`, with its body unread: close it. A refusal of the exchange is a `GrantError`; a 401 `token_stale` of the service is retried once with a new token and the same body.
- **Take `MapService` from `Services` only.** The token of the user is sent to `Service.Endpoint`. Never fill it from the input of a user or of a model.
- **The list comes in pages.** `ServiceOperations` asks for pages of 500 and follows `next_page_token`; each page is at most 16 MiB, not the whole list, and NICE ends a page early at 4 MiB. When the list changes while it is read (another `ETag` on a later page, or `invalid_page_token`), it is read again from the first page once; a second change is an error. A NICE before paging is asked once more without it.
- **Caching.** `ETag` stands for the whole list of the user, and `CatalogVersion` for the catalog of the service. `ServiceOperationsIfChanged` sends the tag with the first page and returns `changed == false` and no operations when NICE answers `304`; the SDK itself keeps nothing.
- **Schemas.** `OperationSchemas` takes any number of keys, asks for each once, 20 to a request, and returns `Schemas` in the order given and `Missing` for the keys the user may not call or that are not active. A failure of any request returns no schemas. `InputSchema` and `Responses` are the JSON NICE sent; `{}` for an operation imported before NICE read schemas. `Truncated` is true when NICE cut a schema at 8 levels, a recursive reference or 64 KiB: tell the model it is not complete. `ResponseSchema(status)` gives the body schema for a status: exact, then `2XX`, then `default`.
- **Secrets.** `RedactSecrets(schema.ResponseSchema(resp.StatusCode), body)` removes every property marked `x-secret: true` in the document of the service, also in arrays, `allOf`/`oneOf`/`anyOf` and `additionalProperties`, before the answer reaches a model or a log. Parts under a cut schema are not followed, and a body that is not JSON is an error.
- **Policy stays in the application.** The SDK does not look at `Sensitive`, does not ask for an approval, does not limit writes, and does not compare the query and the body with `RequestFields` or `InputSchema`. Request fields may be replaced by a catalog administrator; `InputSchema` always follows the document. It also builds no tool definition for a model.
- **Calls over many projects** cost one exchange per project, and `/oauth/token` is rate limited per client (30 a minute by default).
- **It needs a NICE that has the two operations**, which are newer than NICE v1.0.0; an older NICE answers `404`. Before NICE served schemas, request fields carry no description, format or enum, the list has no `ETag`, and `OperationSchemas` is a `404` `APIError`. A delegated token exchanged before NICE was upgraded is answered `403 delegation_not_allowed` until it is exchanged again, at most its lifetime of 30 minutes.

[`examples/exchange`](examples/exchange/main.go) prints the map at `/services`, the operations at `/operations` (with `?etag=`), schemas at `/schemas?keys=`, and calls a read operation at `/call/{operation}` with its secrets removed.

## Signing out and switching accounts

A user who signs in with NICE has two sessions: the one of your application, which holds the refresh token, and the one of NICE in the browser. They end separately.

- **`Disconnect`** revokes the refresh token at NICE (`/oauth/revoke`) and forgets the subject. It runs on the server and does not need the browser. The NICE session stays: the next sign-in completes at once with the same account.
- **`EndSessionURL`** is where the browser goes so that NICE ends its own session (`/oauth/end_session`), and the tokens issued through it stop being renewed in every application. The next sign-in asks for the password. Only the browser can do it, since NICE reads its own cookie.

Use them in this order:

```go
// "Switch account": revoke, end the local session, then let NICE show its account chooser.
if err := c.Disconnect(ctx, subject); err != nil {
	// NICE cannot be reached: keep the user signed in and let them try again.
}
authURL, err := c.AuthorizeURL(ctx, credentials.ConnectRequest{
	Subject: subject, Session: sessionID, RedirectURI: callbackURL, Prompt: credentials.PromptSelectAccount,
})

// "Sign out": revoke, end the local session, then end the NICE session.
if err := c.Disconnect(ctx, subject); err != nil { /* as above */ }
endURL, err := c.EndSessionURL(credentials.EndSessionRequest{
	PostLogoutRedirectURI: "https://app.example.com/signed-out", // optional
	IDTokenHint:           idToken,                              // optional: Connection.IDToken
})
```

- **`Prompt`**: `PromptSelectAccount` shows the account chooser, `PromptLogin` asks for the password again, and `PromptNone` signs in without any page or fails. With `PromptNone` and no NICE session, `HandleCallback` returns a `GrantError` with code `login_required`: treat it as "not signed in", not as a failure. Any other value is refused. `LoginHint` names the email NICE offers first.
- **`PostLogoutRedirectURI`** must be registered as a post-logout redirect URI of the OAuth client. NICE ends its session before checking it, so with an unregistered one the user is signed out but stays on a `400 invalid_request` (`post_logout_redirect_uri invalid`) of NICE. Without it, NICE shows its own signed-out page.
- **`Connection.IDToken`** is returned by `HandleCallback` and is not kept in the `Store`. It names the user (email, name): keep it in the session on the server only, if at all. The hint is optional, since the `client_id` in the URL already names the client, and an expired one is accepted.
- **Access tokens still work until they expire.** Neither call recalls an access token that a service verifies offline. It stops working at its `exp`, at most the access token TTL of NICE.

[`examples/connect`](examples/connect/main.go) has `/switch-account` and `/logout`.

## Reading errors

```go
var grant *credentials.GrantError
var api *credentials.APIError
switch {
case errors.As(err, &grant) && grant.Permanent: // NICE refused for good: replace the key or ask the user to sign in again
case errors.As(err, &grant):                    // NICE refused this request only (e.g. access_denied)
case credentials.IsTemporary(err):              // NICE cannot be reached, or answered 5xx or 429: try again later
case errors.As(err, &api):                      // the NICE API refused (Contexts, Services, ServiceOperations), e.g. 403 user_required
case errors.Is(err, credentials.ErrForeignHost): // a request to another host than the service of this client
case errors.Is(err, credentials.ErrInvalidOperationCall): // CallOperation sent nothing: fix the call
}
```

## Security rules

- **HTTPS.** The address of NICE and the address of a service must be `https`. `http` is accepted for loopback (`localhost`, `127.0.0.0/8`, `::1`), so a local stack needs no setting. For a network where TLS ends somewhere else, set `AllowInsecureHTTP` in the `Config`; no environment variable does it.
- **No redirect to NICE.** The calls of the SDK to NICE follow no redirect, so a secret is never sent to where a redirect points.
- **Secrets are not printed.** `Config`, `ExchangeConfig`, `FeedConfig`, `Token`, `Connection`, and `EndSessionRequest` hide their secret when printed or logged. The JSON form of a `Token` stays whole because a `Store` keeps it that way: do not log a struct that holds a `Token` through a JSON encoder.
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
