# Token verification contract

This document is the contract for every service registered in the NICE catalog. Clients call a service directly with an access token from NICE, and NICE is not on the request path. So **the service must verify the token itself** and enforce the permission of each operation. NICE cannot force this from its side; this contract and the shared test vectors keep verification correct.

The reference library in Go is the `verify` package of this repo (`github.com/ABA-Developer/nice-auth-sdk/verify`). An implementation in another language must give the same answer for every vector in `verify/testdata/vectors.json`.

## Token shape

An RS256 JWT from NICE. One token stands for one principal, one org, one project, and **one** service. The claims a service uses:

| Claim | Meaning |
|---|---|
| `iss` | the NICE issuer; must match the configured one exactly |
| `aud` | the slug of this service; must be exactly one value |
| `exp`, `nbf`, `iat` | lifetime and issue time (Unix seconds) |
| `sub` | `usr_...` or `sa_...` |
| `nice_org_id` | the org: the only tenant key |
| `nice_principal_type` | `user` or `service_account` |
| `prj` | the project of this token |
| `perms` | the permissions of this service that the principal holds in that project; absent when the token carries `perms_ref` |
| `perms_ref` | only on a token whose permissions would make it larger than 6 KB: the reference of the permission list, in place of `perms` (see [Permissions by reference](#permissions-by-reference)) |
| `pv` | the policy version of the org when the token was issued; it orders the token against the access changes of that org (step 7) |
| `act` | only on a token from a token exchange: `{"sub": "<client_id>"}`, the service backend acting on behalf of `sub` |
| `nice_act_as` | only on an act-as token: `org_...` of the platform organization, where the right of a platform operator of this service was decided; `sub` is not a member of `nice_org_id` |

A token from a token exchange (see the NICE API documentation) is verified with exactly the same steps: `act` changes no decision. `sub` is still the user and the permissions are still the user's, so a handler records `act.sub` as the party in between (for example in the audit log of the service: "naia-backend on behalf of usr_..."). In `verify` the value is in `Claims.Actor`; it is empty on an ordinary token. An `act` claim that is not an object makes the token `malformed`.

An act-as token is issued to a platform operator of this service (a holder of the `<slug>.operator` role in the platform organization, see the NICE API documentation) in an organization that is not their own. It is verified with the same steps and its `perms` are the permissions of the operator role, so a service needs no special code to allow it. A handler can read it to show and record that a platform operator is acting in that org: in `verify` the value is in `Claims.ActAs` and `Claims.IsActAs()`; it is empty on an ordinary token.

A token of a non-system client that did not ask for `nice:aud` has the `client_id` of its application as `aud`, so every service refuses it at step 5. A user token for the NICE API (audience `nice`, only for system clients such as the NICE Console) also carries `sid`, the ID of its SSO session. A service token never carries it, and a service does not need to read that claim. The full claims and how to ask for a token are in the NICE API documentation.

## Verification steps per request

The order is fixed: cheap checks first, network calls last. The answer and its reason (`error_description`) are part of the contract.

| # | Check | On failure |
|---|---|---|
| 1 | There is an `Authorization: Bearer`; the token has the shape of a JWS | `401 invalid_token`, `missing_token` or `malformed` |
| 2 | `alg` is in the allowlist **RS256**. `none`, `HS*`, and every other algorithm are refused | `401`, `algorithm_not_allowed` |
| 3 | `kid` is in the JWKS; the signature is valid | `401`, `unknown_key` or `bad_signature` |
| 3a | The payload is a JSON object of claims, and it does not carry both `perms` and `perms_ref` | `401`, `malformed` |
| 4 | `iss` matches exactly | `401`, `wrong_issuer` |
| 5 | `aud` holds **exactly one** value, equal to the slug of the service; a multi-audience token is refused even when this slug is in it | `401`, `wrong_audience` |
| 6 | `exp` has not passed by more than the skew; `nbf` is not more than the skew in the future. The skew is at most **60 seconds** | `401`, `expired` or `not_yet_valid` |
| 6a | `iat` is present and `exp - iat` is at most the TTL plus the skew. A token that lives longer would outlive the deny-set entry of a change that revoked it; the TTL of the service must equal the TTL of NICE (`NICE_ACCESS_TOKEN_TTL`) | `401`, `token_lifetime_exceeded` |
| 7 | Deny-set, for each key of the token (the principal `sub` in its org, the org, the project; for a token with `nice_act_as`, also the principal `sub` in the org `nice_act_as` names). The token is stale when **any** of these holds: `iat` is older than the second of the latest change of the key; the token has `pv`, the change was recorded in the org of the token, and `pv` is lower than the highest `policy_version` of the key; for the key in the `nice_act_as` org, `iat` is not newer than the second of the change | `401`, `token_stale` |
| 7a | Only for a token with `perms_ref`: the permission list it names is known, from the cache or from NICE (see [Permissions by reference](#permissions-by-reference)) | `401 token_stale` when NICE says the reference no longer matches, `503 permissions_unavailable` when the list cannot be had |
| 8 | The org is accepted by the tenant policy of the service (see below) | `403`, `org_rejected` |
| 9 | The operation needs a permission: it must be in `perms`, or in the list `perms_ref` names | `403`, `permission_denied` |
| 10 | When the request names a project, it must equal `prj` | `403`, `project_mismatch` |
| 11 | A sensitive operation: an online access check with NICE | `403 access_denied` or `503 access_check_unavailable` |

A 401 answer carries `WWW-Authenticate: Bearer error="invalid_token", error_description="<reason>"`; without a token it is only `Bearer`. The body is `{"error": "...", "error_description": "..."}`. The reason never contains the token. A client that gets 401 `token_stale` or `expired` renews its token once and sends the request again.

The permission of each operation comes from `x-nice-permission` in the OpenAPI document of the service (or is derived from the tag and the method, with the same rule NICE uses). The name in the catalog must be the name the service enforces; NICE refuses an import that differs.

## JWKS

- Keep the keys by `kid`. Refresh them regularly (every 10 minutes).
- An unknown `kid` triggers a refresh at most **once per minute**, and concurrent requests share that one refresh. Without this limit, random `kid` values become a load on NICE.
- When NICE cannot be reached, keep using the last valid keys. A key that was replaced stays in the JWKS for the token TTL plus the skew.
- Keep a copy of the JWKS on disk and read it at start. A service that restarts while NICE is down, without a copy, cannot verify anything and must answer `503`.

## Access change feed

A token carries its permissions for up to 30 minutes, so an access change needs a fast path. A service reads `GET /api/v1/access-changes` (see the NICE API documentation) with the API key of a Service Account that holds the `nice.service` role:

- **At start**, replay from `now - (TTL + skew)`, so that a token revoked while the service was down is not accepted again.
- Then keep reading with `after_seq` and `wait_seconds=25`. On failure, try again with a backoff (1 second up to 30 seconds).
- Each change sets an entry on **one** key: the principal in that org when there is a `principal_id`, otherwise the project when there is a `project_id`, otherwise the org. The entry keeps the second of the latest change (`occurred_at`) and the highest `policy_version` with the org it was recorded in.
- `iat` has a resolution of one second, so a token issued in the same second as a change cannot be ordered by time. `policy_version` orders them: NICE raises the policy version of an org in the transaction that records each change, and puts the version it read before the permissions into `pv`. A token whose `pv` is lower than the version of the change was issued before it and is refused; one whose `pv` is equal or higher was issued after it. A token without `pv`, or a feed without `policy_version`, falls back to time alone. The act-as key compares time only (its changes are in another org than `pv`), and refuses a token of the same second, since NICE issues no act-as token once the operator role is gone.
- Keep an entry only for the TTL plus the skew; older tokens have expired by themselves.
- `catalog_changed` sets a `not_before` like any other entry: the catalog of a service changed (for example an operation was archived or a permission retired), and every affected principal gets an entry of its own, so its old token is refused with `token_stale` and the client gets a new one with the current `perms`.
- The right of a platform operator (the `<slug>.operator` role) changes in the platform organization: the binding is removed, the user leaves the platform organization, or the role changes. The entry is that principal in the platform organization, and an act-as token issued earlier is refused because step 7 also checks the principal key in the `nice_act_as` org.
- `role_changed` carries neither a `principal_id` nor a `project_id`, so it sets a `not_before` on the org: every token of that org issued earlier is refused with `token_stale`, and the client renews it with its refresh token.

**Degraded mode.** When the feed has not answered for more than two `wait_seconds`, the service logs and counts it. Ordinary operations are still served, with staleness bounded by the token TTL. Sensitive operations still use the online check. A service never goes down only because the feed is cut.

## Sensitive operations

An operation declared `x-nice-sensitive: true` in the OpenAPI document is checked online with NICE on every request, not only from `perms`. When the check cannot be made, the answer is `503` (fail closed). The check calls `POST /api/v1/access-checks` on the public address of NICE with the `ApiKey` of a Service Account that holds the `nice.service` role (permission `nice.platform.access.check`); the answer has `allowed`, `reason`, and `policy_version`. For a token with `nice_act_as`, the request carries `"act_as": true`, so NICE decides it from the operator role of that service, not from membership; without it, an operator who is not a member gets `allowed = false`. The Go library provides `verify.NewHTTPChecker(baseURL, apiKey)`, which sends `act_as` by itself.

## Permissions by reference

A token must fit in an HTTP header, so NICE keeps it under 6 KB. When the permissions of a principal on one service would make the token larger (some 65 to 100 permissions, depending on their names), NICE issues the token without `perms` and with `perms_ref`: the reference of the permission list it decided. Every other claim is the same, and a token that fits is issued as before. A service token never carries both claims.

**The reference.** `perms_ref` is `v1.` followed by the SHA-256, in base64url without padding, of the permission names sorted by byte, without duplicates, joined by one newline (`\n`). It is the hash of the content, so two principals that hold the same permissions on a service carry the same reference, in any org, and a list that hashes to the reference is the list the token was issued with. In `verify` the function is `PermsRef`.

**Resolution.** A verifier that meets a reference it does not know asks NICE once: `POST /api/v1/permission-resolutions` on the public address of NICE, with the `ApiKey` of a Service Account that holds the `nice.service` role (permission `nice.platform.access.check`, the key of the access check and of the feed). The request names the principal of the verified token and the reference:

```json
{ "principal_type": "PRINCIPAL_TYPE_USER", "principal_id": "usr_...", "organization_id": "org_...",
  "project_id": "prj_...", "service": "navi", "act_as": false, "perms_ref": "v1...." }
```

`principal_type` is `PRINCIPAL_TYPE_SERVICE_ACCOUNT` for a Service Account, `service` is `aud`, and `act_as` is `true` for a token with `nice_act_as`. NICE computes the permissions the principal holds now and answers `{"match": true, "permissions": [...]}` when their reference is the one sent, and `{"match": false}` when it is not: the permissions changed since the token was issued, or the principal lost its access (the org or project is no longer active, the membership or the Service Account is gone, the service is no longer active in the project). NICE keeps nothing about the tokens it issued.

The rules a verifier follows:

- Resolve only after steps 1 to 7 passed, so a token that is not valid never makes the service call NICE.
- A reference whose version is not `v1.` cannot be checked: `503 permissions_unavailable`, without asking NICE.
- Compute the reference of the list NICE answers with, and use the list only when it equals `perms_ref`. Any other list is `503 permissions_unavailable` and is not kept.
- Keep the list by its reference, in a cache with a bounded number of entries. A reference never goes stale, so an entry needs no expiry; a token after a refresh, and a token of another principal with the same reference, are served from the cache without asking NICE. The handler sees the list as the permissions of the token.
- `match` false means the token is stale: `401 token_stale`, the same answer as step 7, so the client renews its token and gets one with the reference of its current permissions. Remember that token by its `jti` until its `exp`, in a bounded memory, so the same token does not make the service ask again. Remember the token, not the reference: the same reference still names the permissions of every principal that did not change.
- When the list is not in the cache and cannot be had (no resolver is configured, NICE cannot be reached or does not answer in time, the answer is not valid), the answer is `503 permissions_unavailable` (fail closed). A token with `perms`, and a token whose reference is in the cache, are still served while NICE is down.
- Concurrent requests that need the resolution of the same principal and reference share one call to NICE.

Revoking access works as for any other token: the cache holds permission lists, not decisions about a principal, and a token issued before an access change is refused by the deny-set of the feed.

The Go library provides `verify.NewHTTPResolver(baseURL, apiKey)` for `Config.Resolver`. `Config.Permissions` takes a `PermissionCache` (`NewPermissionCache`), which several verifiers may share; `WithStore` puts a `PermissionStore` of the service behind its memory, to share the lists between replicas or keep them over a restart. A list from the store is used only when it hashes to the reference, so the store needs no more trust than a cache.

## Tenants

A tenant is a NICE org:

- A service that separates data by tenant uses `nice_org_id` from the verified token as the tenant key, and **never** decides the tenant from client input (a header, a parameter, the body). Without a proxy, no header from NICE can be trusted.
- The service chooses how an org becomes known: created on first use (a valid token already proves the entitlement and the activation), an allow list the service administrator fills, or a table from `nice_org_id` to the tenants the service already has, for an existing service. An org that is refused gets `403 org_rejected`.
- A service that does not separate data by tenant ignores `nice_org_id` but still enforces permissions.

## Test vectors

`verify/testdata/vectors.json` holds a JWKS and the vectors (the tokens are already signed). The format:

```json
{
  "version": 3, "issuer": "...", "service": "navi", "jwks": { "keys": [] },
  "vectors": [{
    "name": "stale_principal", "description": "...", "token": "<jwt>", "now": 1793329000,
    "request": { "permission": "navi.orders.read", "project": "prj_...", "sensitive": false, "client_tenant": "org_..." },
    "changes": [{ "principal_id": "usr_...", "organization_id": "org_...", "project_id": "", "kind": "principal_disabled", "occurred_at": 1792000000, "policy_version": 13 }],
    "tenant": { "policy": "allow_all | allow_list | provision", "orgs": ["org_..."] },
    "check": "allow | deny | down",
    "resolve": { "answer": "match | mismatch | down", "permissions": ["navi.orders.read"] },
    "expect": { "status": 401, "error": "invalid_token", "description": "token_stale", "tenant": "org_...", "actor": "naia-backend", "act_as": "org_..." }
  }],
  "perms_refs": [{ "permissions": ["navi.routes.read", "navi.orders.read"], "perms_ref": "v1...." }]
}
```

A runner builds a verifier with `iss`, `service`, the JWKS, a clock fixed at `now`, a skew of 60 seconds, and a TTL of 30 minutes; applies `changes` as if they came from the feed (`occurred_at` in Unix seconds, `policy_version` when present); sends a request with `Authorization: Bearer <token>`, plus the project and client tenant headers when there are any; and compares the status, `error`, `error_description`, and (for a 200) the tenant, the actor (`act.sub`, empty when there is none), and the `nice_act_as` (empty when there is none) that the handler sees. The vectors `valid_act_as_token` and `stale_act_as_operator` test an act-as token that is valid and one that is stale because of a change of the principal in the `nice_act_as` org. Version 2 adds the lifetime check (`lifetime_exceeds_ttl`, `missing_iat`) and the policy version (`stale_same_second_by_policy_version`, `issued_after_change_same_second`, `policy_version_other_org`, `stale_act_as_same_second`, `stale_without_pv`, `same_second_without_pv`).

Version 3 adds the permissions by reference. A vector with `resolve` runs with a resolver that gives that answer to the resolution of `perms_ref`: `match` answers with `permissions`, whatever their reference is, `mismatch` answers that the reference does not match, and `down` cannot be reached; a vector without `resolve` runs without a resolver. The vectors are `perms_ref_resolved`, `perms_ref_permission_missing`, `perms_ref_mismatch`, `perms_ref_resolution_down`, `perms_ref_other_list`, and `perms_and_perms_ref`. `perms_refs` holds permission lists with the reference an implementation must compute for each, which checks the order, the duplicates, and the encoding.

A new implementation must pass **every** vector before it is integrated.

To add a vector: `go test ./verify -run TestWriteVectors -update-vectors`. The vectors already in the file are kept as they are, and a new vector is signed with a new key added to the JWKS (`vector-key-2`, and so on), so other implementations only need to pull the addition. Delete the file first to sign every vector again with one key. Commit the result after reviewing the diff.
