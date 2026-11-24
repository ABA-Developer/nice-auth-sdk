// Package credentials gets and keeps NICE access tokens for a caller of shared
// services. A token is for one service and one project, lives 30 minutes, and
// is renewed before it expires so that the caller keeps working while NICE
// is down for a while.
//
// The behaviour is the one the token client contract asks for: tokens are
// cached per (subject, organization, audience, project); the ones in use are
// renewed in the background after about ten minutes, one renewal at a time,
// with a backoff when NICE does not answer; a session that NICE ended (invalid_grant) is
// reported to the application and not retried; and a request answered 401
// token_stale renews its token once and is sent again.
//
// A request carries the token through Client.Do, or through Client.Transport and
// Client.HTTPClient, which give an http.RoundTripper and an *http.Client for one
// Key and one service address so that any HTTP library or generated client can
// call the service. That transport sends the token to the origin of the service
// only: a request or a redirect to another host fails with ErrForeignHost. A
// Service Account can be built from the environment with NewFromEnv (or
// ConfigFromEnv, to set more fields before New), which reads NICE_ISSUER,
// NICE_SA_ID and NICE_SA_API_KEY.
//
// The secret and the tokens travel over https only. The address of NICE
// (Issuer) and the address of a service must be https; plain http is accepted
// for loopback (localhost, 127.0.0.0/8, ::1), so a local stack needs nothing,
// and for any other host only with AllowInsecureHTTP set in the Config, for a
// network where TLS ends somewhere else. No environment variable sets it. The
// calls to NICE follow no redirect, so the secret never goes where a redirect
// points. Config, ExchangeConfig, Token and Pending print and log without their
// secret.
//
// A Key without an Audience asks for the NICE API (audience nice), which NICE
// grants only to its system clients such as the NICE Console. An application
// registered in a project names the service it calls; a client of a tenant
// organization may leave Project empty to use its own project, and is refused
// any other project.
//
// A backend that holds the refresh tokens of many users (KindBFF) moves a
// user's grant to another organization with no redirect: Token with Key.Org
// set names that organization in the refresh, along with the base scopes of
// Config.BaseScopes, which every refresh repeats. NICE keeps the organization
// in the refresh token, so such a backend keeps the active organization in each
// user's session and names it on every call; two requests of one user for two
// organizations then each get a token of their own. A refusal (access_denied,
// invalid_scope) is returned to the caller and changes nothing else: the
// session lives on and other keys are served. A move drops the tokens of that
// user kept without an organization.
//
// ExchangeClient is the mode for the backend of a service that calls other
// services on behalf of the user whose request it serves: it exchanges the
// user's token (RFC 8693 token exchange) with the secret of its confidential
// service client, keeps the result per (subject token, organization, project,
// audience) no longer than the user's token, and never holds a refresh token.
// A kept token is found by the subject token itself, never by claims read from
// a token the client did not verify.
//
// ExchangeClient.Contexts lists the organizations and projects of a user, and
// the services the user may use in each, before a project is known: it trades
// the subject token for a delegated token of the NICE API (Key{Audience:
// "nice"}) and reads every page of GET /api/v1/me/contexts. A backend that
// holds the refresh token of a user through a service client passes the
// sign-in token of Client.SignInToken, with an ExchangeClient of the same
// service client; NICE accepts a sign-in token as the subject of an exchange
// for the NICE API only. The backend of a service passes the token of the
// request. The chosen organization and project then go in Key.Org and
// Key.Project. An answer of the NICE API other than 2xx is an APIError.
package credentials
