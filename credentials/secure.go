package credentials

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// checkURL refuses an address that would carry a secret or a token in the clear. https is always accepted; http is
// accepted for loopback (localhost, 127.0.0.0/8, ::1) and, when allowInsecure is set, for any host. what names the
// address in the error, which never shows a password of the URL.
func checkURL(what, raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("niceauth: %s must be an absolute https URL", what)
	}
	return u, checkParsed(what, u, allowInsecure)
}

func checkParsed(what string, u *url.URL, allowInsecure bool) error {
	if u == nil || u.Host == "" {
		return fmt.Errorf("niceauth: %s must be an absolute https URL", what)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("niceauth: %s %s is not https; plain http is accepted for loopback only, or set AllowInsecureHTTP", what, u.Redacted())
	}
	return fmt.Errorf("niceauth: %s %s must be an https URL", what, u.Redacted())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// originOf is the scheme, host and port of u, with the default port written out.
func originOf(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// noRedirect is hc for the calls to NICE: it does not follow a redirect, so a secret is never sent to the place a
// redirect names. hc itself is left as it is.
func noRedirect(hc *http.Client) *http.Client {
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// redirectTarget names the host a redirect answer points to, for an error.
func redirectTarget(resp *http.Response) string {
	if u, err := url.Parse(resp.Header.Get("Location")); err == nil && u.Host != "" {
		return u.Host
	}
	return "another address"
}

// ErrForeignHost is returned by the transport of Client.Transport and Client.HTTPClient for a request, or a redirect,
// to another origin than the service it was made for. The token is not added and the request is not sent.
var ErrForeignHost = errors.New("niceauth: the request is not for the service of this transport")
