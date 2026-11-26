# Changelog

## v0.3.0

### Added

- `ServiceOperations` reads the list in pages of 500, following `next_page_token`, and bounds each page to 16 MiB instead of the whole list. When the list changes while it is read (another `ETag` on a later page, or `invalid_page_token`), it is read again from the first page once; a second change is an error. A NICE before paging, which refuses `page_size`, is asked once more without it.
- `ServiceOperation.Description`, and `RequestField.Description`, `Format`, `Enum` and `EnumTruncated`, as NICE reads them from the document of the service. `ServiceOperations.CatalogVersion` and `ETag`.
- `ExchangeClient.ServiceOperationsIfChanged` sends the `ETag` of an earlier answer as `If-None-Match` and returns `changed == false` and no operations on `304`.
- `ExchangeClient.OperationSchemas` returns the full input and response schemas of operations from `GET /api/v1/me/services/{slug}/operation-schemas` (`OperationSchemas`, `OperationSchema`): any number of keys, each asked once, 20 to a request, schemas in the order given and `Missing` once each. A failure of any request returns no schemas. `OperationSchema.ResponseSchema(status)` picks the body schema of a status: exact, then range, then `default`.
- `RedactSecrets` removes the properties a schema marks `x-secret: true` from a JSON body, keeping the order and the numbers of the rest.
- The calls to the NICE API ask for gzip and bound the body after it is decompressed.
- `examples/exchange` has `/operations` (with `?etag=`) and `/schemas?keys=`, and `/call/{operation}` removes secrets from the answer.

Nothing is removed or changed for existing callers. Paging and schemas need NICE with `add-sdk-operation-schemas` and `add-operation-schemas`; against an older NICE the new fields are empty and `OperationSchemas` is a `404` `APIError`.

## v0.2.4

### Added

- `ExchangeClient.Services` returns the service map of the user of a subject token from `GET /api/v1/me/services`: the organizations in the order NICE gives, the projects of each with the slugs of the other services the user holds a permission of, `projects_truncated`, and the name, description, endpoint and base path of every listed service once (`ServiceMap`, `MapService`, `MapOrganization`, `MapProject`). It reads every page (at most 100, each body at most 4 MiB) and returns an error and no map beyond the bounds.
- `ExchangeClient.ServiceOperations` returns the operations of one service whose permission the user holds, from `GET /api/v1/me/services/{slug}/operations`, with their method, path, summary, permission, tag, sensitive mark, headers and request fields, and the tags of the service (`ServiceOperations`, `ServiceOperation`, `OperationHeader`, `RequestField`, `OperationTag`). An empty slug is refused before any call, the slug is sent as one escaped path segment, and the body is at most 16 MiB.
- Both use the delegated token of the NICE API that `Contexts` uses, so the three share one exchange per subject token and exchange once more on `token_stale`. Their errors are those of `Contexts` (`GrantError`, `APIError`, `TemporaryError`).
- `ExchangeClient.CallOperation` sends one call of a listed operation on behalf of a user (`OperationCall`): the address is the endpoint and base path of the service and the path of the operation, every `{name}` of the path is replaced by its value as one escaped segment, the headers of the operation replace those of the caller, and it is sent through `DoAs` with a token for the service in the named organization and project. The answer of the service is returned as it is. A call that is not complete, or a path parameter that is missing, unknown, empty, `.` or `..`, or that holds a slash, a backslash or a control character, is refused before anything is exchanged with an error that wraps `ErrInvalidOperationCall`.
- `examples/exchange` prints the service map at `/services` and calls a read operation found through it at `/call/{operation}`. The README has a section on finding services and operations for an agent.

These need a NICE that has the two operations; an older NICE answers `404`.

## v0.2.3

### Breaking

- `verify` holds no credential of NICE. NICE drops the `nice.service` role and its API key, so a shared service no longer needs a Service Account:
  - `FeedConfig.APIKey` is gone. `StartFeed` reads `GET /api/v1/access-changes` without an `Authorization` header, and a `FeedConfig` with only its defaults starts.
  - `NewHTTPChecker(baseURL)` and `NewHTTPResolver(baseURL)` take no API key. They send the token of the request being handled as `Authorization: Bearer`, and NICE reads the principal, the organization, the project, `nice_act_as` and `perms_ref` from it. The body of the check is `{"permission": "<name>"}` only (no `principal_*`, `organization_id`, `project_id`, `act_as`), and that of the resolution is `{}`. A `401` from NICE fails closed like any other error, with `503`.
  - `HTTPChecker` and `HTTPResolver` take the token from the `Claims` that `Verify` returned, which keep it in a field that JSON, `fmt` and `slog` do not show. `Claims` built another way carry no token, and the call is an error (fail closed). The `AccessChecker` and `PermissionResolver` interfaces are unchanged.
  - The feed names a change by `key` and `org_key` in place of `organization_id`, `principal_id`, `project_id` and `key_id`. The verifier computes the same keys for each token and compares `policy_version` only when `org_key` is the org key of the token. A verifier of this version needs a NICE that sends the keys, and an older verifier reads no change from it.
- The shared vectors are version 4: each change carries `key` and `org_key` in place of `principal_id`, `organization_id` and `project_id`. The vectors and their answers are those of version 3.

### Added

- `FeedKey` computes the key of a change: `"v1."` and the base64url SHA-256, without padding, of the lines joined by a newline (`"p", sub, org`; `"j", prj`; `"o", org`), the encoding of `PermsRef`. The vector file lists lines with their key in `feed_keys`.

## v0.2.2

### Added

- `ConnectRequest.Prompt` sends `prompt` with the sign-in: `PromptSelectAccount` shows the account chooser of NICE, so a user who signed out of the application can pick another account instead of being signed in again with the same one; `PromptLogin` asks for the password again; `PromptNone` signs in without a page, and `HandleCallback` then returns a `GrantError` with code `login_required` when the browser has no NICE session. `AuthorizeURL` refuses any other value and keeps no state for it.
- `ConnectRequest.LoginHint` sends `login_hint`, the email NICE offers first.
- `Connection.IDToken`: `HandleCallback` returns the ID token NICE gave with the code. It is not kept in the `Store`, and `Connection` hides it when printed or logged.
- `Client.EndSessionURL` builds the RP-initiated logout address (`/oauth/end_session`) with `client_id` and, when set, `post_logout_redirect_uri`, `state` and `id_token_hint`. It makes no request; the browser goes there after `Disconnect`, and NICE ends its session so the next sign-in asks for the password. `EndSessionRequest` hides the hint when printed or logged.
- `examples/connect` has `/switch-account`, and `/logout` also ends the NICE session (`POST_LOGOUT_URL`). The README has a section on signing out and switching accounts.

## v0.2.1

### Added

- `ExchangeClient.Contexts` lists the organizations and projects of the user of a subject token from `GET /api/v1/me/contexts`, with the services of each project, and `act_as` and `projects_truncated` of each organization. It reads every page (at most 100, each body at most 4 MiB) and returns an error and no list beyond the bounds. The delegated token of the NICE API is kept per subject token and exchanged once more on `token_stale`, as for `DoAs`. Use it with the sign-in token of `Client.SignInToken` or with the token of a request.
- `APIError` (`Status`, `Code`, `Message`, `RequestID`) for an answer of the NICE API other than 2xx. A 5xx or 429 comes wrapped in a `TemporaryError`, so `IsTemporary` holds and `errors.As` still finds the `APIError`. Its message never holds a token or the raw body.

## v0.2.0

### Added

- `verify` reads `perms_ref`. NICE keeps a token under 6 KB; when the permissions of a principal on one service would make it larger, the token carries `perms_ref`, the reference (a hash) of its permission list, in place of `perms`. With `Config.Resolver` the verifier asks NICE for the list once per reference (`POST /api/v1/permission-resolutions`), checks that it hashes to the reference, keeps it, and fills `Claims.Permissions`, so `Require` and handlers need no change. `NewHTTPResolver(baseURL, apiKey)` is the resolver for NICE; it takes the API key of the access check and of the feed (a Service Account with the `nice.service` role), and follows the same address and redirect rules as `HTTPChecker`.
- `PermissionCache` (`NewPermissionCache`, `Config.Permissions`) keeps the resolved lists by reference, 1,024 by default, and may be shared by several verifiers. `WithStore` puts a `PermissionStore` of the service behind its memory, to share the lists between replicas or keep them over a restart; a list from the store is used only when it hashes to its reference.
- `PermsRef` computes the reference of a permission list. `ReasonPermsDown` (`permissions_unavailable`) is the reason of the new 503.
- The shared vectors are version 3: six `perms_ref` vectors with the answer of the resolution in `resolve`, and `perms_refs`, permission lists with the reference to compute.

Set `Config.Resolver` in every service before NICE issues such tokens. A verifier of this version without a resolver refuses a `perms_ref` token with `503 permissions_unavailable`; an older verifier reads it as a token without permissions and answers `403`. When NICE says the reference no longer matches (the permissions changed since the token was issued), the answer is `401 token_stale` and the client renews its token. A token that carries both `perms` and `perms_ref` is refused as `malformed`.

### Security

- `FileStore` named two different subjects alike: its escape (`~` and a hex number of any length) wrote `bob.example` and `bobˮxample`, or any two invalid UTF-8 strings, to the same files. A user of the application whose subject collided with another one's read that user's refresh token and got NICE tokens of the other account. Each byte outside `[A-Za-z0-9_-]` is now written as `.` and two hex digits, so every subject has files of its own. `DeleteSubject` no longer uses a glob, so a store directory whose name holds `[`, `*` or `?` still works.
- `verify` forgot a revocation `TokenTTL` plus the skew after it happened. When NICE issued tokens that live longer than `Config.TokenTTL` (`NICE_ACCESS_TOKEN_TTL` raised, `TokenTTL` left at its default), a revoked token was accepted again until it expired. A token whose `exp - iat` exceeds `TokenTTL` plus the skew, or that has no `iat`, is now refused.
- `verify` did not refuse a token issued in the same second as the change that revoked it: the deny-set compared `iat` with the second of the change, so such a token was served until it expired (up to 30 minutes). The deny-set now also keeps the highest `policy_version` the feed gives for each key, and a token whose `pv` is older, in the same organization, is refused with `token_stale` whatever the second. A token without `pv` is still judged by time; for the principal key in the `nice_act_as` organization a token of the same second as the change is refused too. Needs a NICE that reads the policy version before the permissions when it issues a token.

### Breaking

- `verify`: a token that lives longer than `Config.TokenTTL` plus the skew is refused with `401 invalid_token`, `token_lifetime_exceeded`, and the verifier logs a warning at most once a minute with both durations. A service whose `TokenTTL` is shorter than `NICE_ACCESS_TOKEN_TTL` of NICE refuses every token until the two are equal. Both default to 30 minutes.
- `FileStore`: a subject made only of ASCII letters, digits, `_` and `-` keeps its files and its session. Any other subject (an email, a name) is stored under a new name: its user connects again once after the upgrade. The files of the old form (names with `~`) are never read again; delete them with `find <dir> -name '*~*' -delete` once every process runs the new version.

## v0.1.0

First public release, under Apache-2.0. The code comes from `pkg/niceauth` in the NICE repo, after a security hardening pass:

- NICE and service addresses must be `https`; plain `http` works for loopback only, or with `AllowInsecureHTTP`.
- Calls from the SDK to NICE don't follow redirects.
- `Client.Transport` and `Client.HTTPClient` are bound to one service address and refuse any other host with `ErrForeignHost`.
- `ExchangeClient` caches tokens per subject token.
- Configs, tokens, and clients don't print their secrets.
- Runnable examples in `examples/` for four roles: `service_account`, `service`, `exchange`, `connect`.
- `layout_test.go` keeps `verify` and `credentials` from importing each other.
