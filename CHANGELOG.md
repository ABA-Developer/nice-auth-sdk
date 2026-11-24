# Changelog

## Unreleased

### Added

- `ExchangeClient.Contexts` lists the organizations and projects of the user of a subject token from `GET /api/v1/me/contexts`, with the services of each project, `act_as` and `projects_truncated` of each organization, and the services of an organization once NICE sends them. It reads every page (at most 100, each body at most 4 MiB) and returns an error and no list beyond the bounds. The delegated token of the NICE API is kept per subject token and exchanged once more on `token_stale`, as for `DoAs`. Use it with the sign-in token of `Client.SignInToken` or with the token of a request.
- `APIError` (`Status`, `Code`, `Message`, `RequestID`) for an answer of the NICE API other than 2xx. A 5xx or 429 comes wrapped in a `TemporaryError`, so `IsTemporary` holds and `errors.As` still finds the `APIError`. Its message never holds a token or the raw body.

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
