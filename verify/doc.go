// Package verify verifies NICE access tokens inside a shared service, so the
// service decides access from the token without asking NICE on each request.
//
// A service builds one Verifier, wraps its handler with Middleware, guards each
// operation with Require, and (to refuse tokens issued before an access change)
// starts the change feed with StartFeed. The behaviour is the verification
// contract in docs/token-verification.md and is tested against the shared test
// vectors in testdata/vectors.json.
//
// The addresses of NICE the service calls (the JWKS, the feed, the access
// check) must be https; plain http is accepted for loopback (localhost,
// 127.0.0.0/8, ::1) and for any other host only with Config.AllowInsecureHTTP
// or HTTPChecker.WithInsecureHTTP. Those calls follow no redirect, so the API
// key is never sent, and the keys never taken, where a redirect points.
package verify
