package credentials

import (
	"errors"
	"net/url"
)

// EndSessionRequest is the sign-out of a user from NICE itself, not only from the application.
type EndSessionRequest struct {
	// PostLogoutRedirectURI is where NICE sends the browser afterwards. It must be registered as a
	// post-logout redirect URI of the OAuth client; NICE refuses one that is not, after ending the session.
	// Empty shows the signed-out page of NICE.
	PostLogoutRedirectURI string
	// State comes back unchanged on PostLogoutRedirectURI; optional.
	State string
	// IDTokenHint is Connection.IDToken of the user, if the application kept it; optional, an expired one
	// is accepted. It must have been issued to this client.
	IDTokenHint string
}

// EndSessionURL returns the address to send the user's browser to so that NICE ends its session (RP-initiated
// logout): the user signs in again with a password next time, in every application, and the tokens issued through
// that session stop being renewed. It makes no request; NICE ends the session from its own cookie, so it must be
// the browser that goes there. Call Disconnect first: it revokes the refresh token from the server even when the
// browser no longer has a NICE session.
func (c *Client) EndSessionURL(req EndSessionRequest) (string, error) {
	if c.isServiceAccount() {
		return "", errors.New("niceauth: a Service Account has no NICE session to end")
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if req.PostLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", req.PostLogoutRedirectURI)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	if req.IDTokenHint != "" {
		q.Set("id_token_hint", req.IDTokenHint)
	}
	return c.cfg.Issuer + "/oauth/end_session?" + q.Encode(), nil
}
