// Package niceauth is the Go SDK of NICE: for services that verify NICE access
// tokens and for callers that get them. It has no code of its own; import the
// sub-package for the side you write:
//
//	You write                                         You import
//	a caller that gets tokens and calls services      credentials
//	  (Service Account, BFF, user client, exchange)
//	a shared service that checks the tokens it gets   verify
//
// The import paths are github.com/ABA-Developer/nice-auth-sdk/credentials and
// github.com/ABA-Developer/nice-auth-sdk/verify.
//
// credentials gets, caches and renews NICE access tokens and adds them to the
// requests of the caller, through Client.Do or the *http.Client of
// Client.HTTPClient. verify checks a token inside a service (signature,
// claims, permissions, access changes, tenant) without asking NICE on each
// request.
//
// The two never import each other, and verify needs only the standard library
// and go-jose, so a service that only verifies does not carry the caller side.
package niceauth
