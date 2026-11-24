// Package verify verifies NICE access tokens inside a shared service, so the
// service decides access from the token without asking NICE on each request.
//
// A service builds one Verifier, wraps its handler with Middleware, guards each
// operation with Require, and (to refuse tokens issued before an access change)
// starts the change feed with StartFeed. The behaviour is the verification
// contract in docs/token-verification.md and is tested against the shared test
// vectors in testdata/vectors.json.
//
// A principal that holds more permissions than fit in a token gets one that
// carries perms_ref, the reference of its permission list, instead of perms.
// With Config.Resolver the Verifier asks NICE for that list once, keeps it in a
// PermissionCache, and fills Claims.Permissions, so Require and the handlers
// see every token the same way.
//
// The addresses of NICE the service calls (the JWKS, the feed, the access
// check, the permission resolution) must be https; plain http is accepted for
// loopback (localhost, 127.0.0.0/8, ::1) and for any other host only with
// Config.AllowInsecureHTTP, HTTPChecker.WithInsecureHTTP or
// HTTPResolver.WithInsecureHTTP. Those calls follow no redirect, so the API
// key is never sent, and the keys never taken, where a redirect points.
package verify
