package credentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrInvalidOperationCall is wrapped by the error of CallOperation for a call it refuses before anything is
// exchanged or sent: a service or an operation that is not complete, or a path parameter that is missing, not in
// the path, or not one plain path segment. The message names the parameter, never its value.
var ErrInvalidOperationCall = errors.New("niceauth: invalid operation call")

// OperationCall is one call of an operation of a listed service on behalf of a user.
type OperationCall struct {
	// Service is the service, from ServiceMap.Services. The token of the user goes to Service.Endpoint, so never
	// fill it from the input of a user or of a model.
	Service MapService
	// Operation is the operation, from ServiceOperations.Operations.
	Operation ServiceOperation
	// Org is the organization (org_...) of the call; empty keeps the organization of the subject token.
	Org string
	// Project is the project (prj_...) of the call, one the map lists for the service. Empty keeps the project of
	// the subject token when Org is its organization.
	Project string
	// PathParams gives the value of every {name} of Operation.Path, and of no other name. A value is one path
	// segment: not empty, not "." or "..", without a slash, a backslash or a control character.
	PathParams map[string]string
	Query      url.Values
	// Header is sent with the call. A header of Operation.Headers replaces one of the same name, and Authorization
	// is always the token of the exchange.
	Header http.Header
	// Body is sent as it is, with Content-Type application/json when neither Header nor the operation names one.
	Body []byte
}

var pathPlaceholder = regexp.MustCompile(`\{([^{}/]+)\}`)

// CallOperation sends one call of an operation of a service on behalf of the user of subjectToken. The address is
// Service.Endpoint, Service.BasePath and Operation.Path, with every {name} of the path replaced by its value as one
// escaped path segment; the method is Operation.Method. It is sent through DoAs with a token for (Org, Project,
// Service.Slug): tokens are kept and exchanged as for any other call, calls for different projects each exchange
// once, the address rules of DoAs hold, and a service that answers 401 token_stale gets one new exchange and the
// call once more with the same body.
//
// subjectToken is a token of the user for the service of this client (Client.Token with that audience and a
// project where it is active, or the verified token of the request in the backend of a service). NICE refuses a
// sign-in token as the subject of an exchange for another service: that refusal is returned as a GrantError and
// the service is not called.
//
// The answer of the service is returned as it is, whatever its status, and its body is not read: the caller closes
// it. A call that is not complete or whose path parameters would move the path is refused with an error that wraps
// ErrInvalidOperationCall before anything is exchanged. The SDK checks nothing else: it does not look at
// Operation.Sensitive, does not compare Query and Body with Operation.RequestFields, and does not ask whether the
// project is in the map. The service enforces its permissions, and whether a call needs the approval of the user is
// the choice of the application.
func (x *ExchangeClient) CallOperation(ctx context.Context, subjectToken string, call OperationCall) (*http.Response, error) {
	req, err := operationRequest(ctx, call)
	if err != nil {
		return nil, err
	}
	return x.DoAs(ctx, subjectToken, Key{Org: call.Org, Project: call.Project, Audience: call.Service.Slug}, req)
}

func invalidCall(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOperationCall, fmt.Sprintf(format, a...))
}

// operationRequest builds the request of call, or refuses it.
func operationRequest(ctx context.Context, call OperationCall) (*http.Request, error) {
	svc, op := call.Service, call.Operation
	switch {
	case svc.Slug == "":
		return nil, invalidCall("the service has no slug")
	case svc.Slug == "nice":
		return nil, invalidCall("the NICE API is not a service of the map")
	case svc.Endpoint == "":
		return nil, invalidCall("the service has no endpoint")
	case op.Method == "":
		return nil, invalidCall("the operation has no method")
	case !strings.HasPrefix(op.Path, "/"):
		return nil, invalidCall("the path of the operation must start with a slash")
	case svc.BasePath != "" && !strings.HasPrefix(svc.BasePath, "/"):
		return nil, invalidCall("the base path of the service must start with a slash")
	}
	base, err := url.Parse(strings.TrimRight(svc.Endpoint, "/"))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, invalidCall("the endpoint of the service must be an absolute URL without a user, a query or a fragment")
	}
	path, err := fillPath(op.Path, call.PathParams)
	if err != nil {
		return nil, err
	}
	raw := base.Scheme + "://" + base.Host + strings.TrimRight(base.EscapedPath(), "/") +
		escapeLiteral(strings.TrimRight(svc.BasePath, "/")) + path
	if len(call.Query) > 0 {
		raw += "?" + call.Query.Encode()
	}
	var body io.Reader
	if len(call.Body) > 0 {
		body = bytes.NewReader(call.Body) // NewRequest sets GetBody, so DoAs can send it again
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(op.Method), raw, body)
	if err != nil {
		return nil, invalidCall("the request cannot be built from this service and operation")
	}
	// Names are made canonical so that a header of the operation replaces the caller's in any case, and no
	// Authorization of the caller is left beside the one DoAs sets.
	for name, values := range call.Header {
		if http.CanonicalHeaderKey(name) == "Authorization" {
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	for _, h := range op.Headers {
		if h.Name != "" && http.CanonicalHeaderKey(h.Name) != "Authorization" {
			req.Header.Set(h.Name, h.Value)
		}
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// fillPath replaces each {name} of an operation path by the escaped value of name and returns the escaped path.
// The rules are those of the test request of NICE: every placeholder has a value, no value is left over, and a
// value is one plain path segment, so the path sent is the one the operation names.
func fillPath(path string, values map[string]string) (string, error) {
	inPath := map[string]bool{}
	for _, m := range pathPlaceholder.FindAllStringSubmatch(path, -1) {
		name := m[1]
		if inPath[name] {
			continue
		}
		inPath[name] = true
		v, ok := values[name]
		switch {
		case !ok:
			return "", invalidCall("path parameter %s is missing", name)
		case strings.TrimSpace(v) == "":
			return "", invalidCall("path parameter %s must not be empty", name)
		case v == "." || v == ".." || strings.ContainsAny(v, `/\`):
			return "", invalidCall("path parameter %s must be one plain path segment", name)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f || r == utf8.RuneError {
				return "", invalidCall("path parameter %s holds a control or invalid character", name)
			}
		}
	}
	var extra []string
	for name := range values {
		if !inPath[name] {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return "", invalidCall("path parameters not in the path: %s", strings.Join(extra, ", "))
	}
	var b strings.Builder
	last := 0
	for _, loc := range pathPlaceholder.FindAllStringSubmatchIndex(path, -1) {
		b.WriteString(escapeLiteral(path[last:loc[0]]))
		b.WriteString(url.PathEscape(values[path[loc[2]:loc[3]]]))
		last = loc[1]
	}
	b.WriteString(escapeLiteral(path[last:]))
	return b.String(), nil
}

// escapeLiteral escapes the fixed part of a path, keeping its slashes.
func escapeLiteral(s string) string { return (&url.URL{Path: s}).EscapedPath() }
