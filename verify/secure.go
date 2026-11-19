package verify

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// checkURL refuses an address that would carry the API key in the clear, or bring the keys of NICE over a link
// anyone can change. https is always accepted; http is accepted for loopback (localhost, 127.0.0.0/8, ::1) and,
// when allowInsecure is set, for any host. what names the address in the error, which never shows a password of
// the URL. The credentials package has the same rule; the two packages do not import each other.
func checkURL(what, raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errConfig(fmt.Sprintf("%s must be an absolute https URL", what))
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopback(u.Hostname()) {
			return nil
		}
		return errConfig(fmt.Sprintf("%s %s is not https; plain http is accepted for loopback only, or set AllowInsecureHTTP", what, u.Redacted()))
	}
	return errConfig(fmt.Sprintf("%s %s must be an https URL", what, u.Redacted()))
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// noRedirect is hc for the calls to NICE: it does not follow a redirect, so the API key is never sent to the
// place a redirect names and the keys are never taken from there. hc itself is left as it is.
func noRedirect(hc *http.Client) *http.Client {
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

const redactedMark = "[redacted]"

func redacted(secret string) string {
	if secret == "" {
		return `""`
	}
	return redactedMark
}
