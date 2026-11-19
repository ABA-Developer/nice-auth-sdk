# Changelog

## v0.1.0

First public release, under Apache-2.0. The code comes from `pkg/niceauth` in the NICE repo, after a security hardening pass:

- NICE and service addresses must be `https`; plain `http` works for loopback only, or with `AllowInsecureHTTP`.
- Calls from the SDK to NICE don't follow redirects.
- `Client.Transport` and `Client.HTTPClient` are bound to one service address and refuse any other host with `ErrForeignHost`.
- `ExchangeClient` caches tokens per subject token.
- Configs, tokens, and clients don't print their secrets.
- Runnable examples in `examples/` for four roles: `service_account`, `service`, `exchange`, `connect`.
- `layout_test.go` keeps `verify` and `credentials` from importing each other.
