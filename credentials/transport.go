package credentials

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Do sends req to a service with a token for key. A service that answers 401
// because the token is stale (an access change reached it after the token was
// issued) or expired gets one new token and the request once more. The second answer is returned
// whatever it is. A request with a body is only sent again if req.GetBody is set,
// which http.NewRequest does for the usual body types.
//
// The token goes to the host req names, so name only the service of key; the
// client of HTTPClient refuses any other host and is the safer way to call one
// service. A plain http address that is not loopback is refused before a token
// is asked for, unless Config.AllowInsecureHTTP is set. Config.HTTP follows
// redirects as it is set to: net/http drops the token on a redirect to another
// domain, but not to a subdomain of the first.
func (c *Client) Do(ctx context.Context, key Key, req *http.Request) (*http.Response, error) {
	if err := checkParsed("the request address", req.URL, c.cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	return c.send(ctx, key, req, c.cfg.HTTP.Do)
}

// Transport returns an http.RoundTripper for the service at the address
// service: it adds the token of key to every request and sends it through
// base, with the same renewal and single retry on token_stale or expired as
// Do. A nil base uses the transport of Config.HTTP, or http.DefaultTransport
// when it has none. The request of the caller is not changed: the token is set
// on a copy.
//
// The transport is bound to the origin of service (scheme, host and port; any
// path). A request to another origin, and so a redirect to one, fails with
// ErrForeignHost: no token is asked for and nothing is sent, so a token of the
// service never reaches another host. A service that redirects elsewhere on
// purpose (a download from an object store) is followed by the application
// with a client of its own.
//
// service must be an absolute https URL; plain http is accepted for loopback,
// or with Config.AllowInsecureHTTP.
//
// When no token can be had, RoundTrip returns the error of Token, and the
// service is not called. An http.Client wraps it in a *url.Error, which
// errors.As, errors.Is and IsTemporary see through.
func (c *Client) Transport(key Key, service string, base http.RoundTripper) (http.RoundTripper, error) {
	u, err := checkURL("the service address", service, c.cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = c.cfg.HTTP.Transport
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{c: c, key: key, origin: originOf(u), base: base}, nil
}

// HTTPClient returns an *http.Client for the service at the address service:
// it sends through Transport(key, service, nil), with the timeout, redirect
// policy and cookie jar of Config.HTTP. It calls that service only; see
// Transport.
func (c *Client) HTTPClient(key Key, service string) (*http.Client, error) {
	rt, err := c.Transport(key, service, nil)
	if err != nil {
		return nil, err
	}
	hc := *c.cfg.HTTP
	hc.Transport = rt
	return &hc, nil
}

type transport struct {
	c      *Client
	key    Key
	origin string
	base   http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || originOf(req.URL) != t.origin {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		host := ""
		if req.URL != nil {
			host = req.URL.Host
		}
		return nil, fmt.Errorf("%w: %q is not %s", ErrForeignHost, host, t.origin)
	}
	resp, err := t.c.send(req.Context(), t.key, req, t.base.RoundTrip)
	if err != nil && resp == nil && req.Body != nil {
		_ = req.Body.Close() // a RoundTripper closes the body, even on errors
	}
	return resp, err
}

// send is the loop of Do and Transport: it sends a copy of req with a token for key through send, and on a 401 for a
// stale or expired token drops that token and sends once more.
func (c *Client) send(ctx context.Context, key Key, req *http.Request, send func(*http.Request) (*http.Response, error)) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		tok, err := c.Token(ctx, key)
		if err != nil {
			return nil, err
		}
		r := req.Clone(ctx)
		r.Header.Set("Authorization", "Bearer "+tok.Access)
		if attempt > 0 && req.Body != nil && req.Body != http.NoBody {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
		resp, err := send(r)
		if err != nil || resp.StatusCode != http.StatusUnauthorized || attempt > 0 || !staleChallenge(resp) {
			return resp, err
		}
		if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
			return resp, nil // cannot send it again
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		c.Invalidate(key, tok)
	}
}

func staleChallenge(resp *http.Response) bool {
	h := resp.Header.Get("WWW-Authenticate")
	return strings.Contains(h, "token_stale") || strings.Contains(h, `error_description="expired"`)
}
