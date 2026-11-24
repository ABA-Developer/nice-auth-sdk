package credentials

import (
	"context"
	"errors"
	"time"
)

// signInAudience keys the sign-in token in the cache and the Store. A slug of the catalog never holds a colon, so
// it cannot be the key of a service token.
const signInAudience = "nice:sign-in"

// signInMargin is how long a sign-in token must still live to be handed out: NICE refuses a subject token with
// less than a minute left (subject_token_expiring), and the exchange that follows takes some time.
const signInMargin = 2 * time.Minute

func (k Key) isSignIn() bool { return k.Audience == signInAudience }

// safety is how close to its expiry the token of key is no longer handed out.
func (c *Client) safety(key Key) time.Duration {
	if key.isSignIn() {
		return max(c.cfg.Safety, signInMargin)
	}
	return c.cfg.Safety
}

// SignInToken returns the sign-in token of the connected user subject: the token a refresh with Config.BaseScopes
// only issues to this client for itself, in the organization the refresh token is in, which the refresh leaves
// unchanged. It is the subject token of an exchange for the NICE API, for instance to read the organizations and
// projects of the user with ExchangeClient.Contexts before a project is known:
//
//	signIn, err := c.SignInToken(ctx, subject)
//	contexts, err := x.Contexts(ctx, signIn.Access)
//
// NICE refuses a sign-in token as the subject of an exchange for any other service. The token is kept until close
// to its expiry and is not renewed in the background. The refresh token is used one at a time with the other keys
// of subject, and invalid_grant ends the session as for any refresh.
func (c *Client) SignInToken(ctx context.Context, subject string) (Token, error) {
	if c.isServiceAccount() {
		return Token{}, errors.New("niceauth: a Service Account has no sign-in token")
	}
	if subject == "" {
		return Token{}, errors.New("niceauth: SignInToken needs the subject of a connected user")
	}
	return c.Token(ctx, Key{Subject: subject, Audience: signInAudience})
}
