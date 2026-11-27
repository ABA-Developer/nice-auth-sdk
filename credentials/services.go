package credentials

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// maxOperationsBody bounds the body of one page of the operations of one service. NICE ends a page once it exceeds
// 4 MiB, and one operation stays well below the rest.
const maxOperationsBody = 16 << 20

// operationsPageSize is the page size the SDK asks for; NICE allows at most 500.
const operationsPageSize = 500

// maxOperationsPages bounds the pages of one reading of the operations of a service.
const maxOperationsPages = 100

// ServiceMap is where the user of a subject token may call other services, as NICE lists it: the organizations in
// the order NICE gives, each with its projects and the services the user holds a permission of in each.
type ServiceMap struct {
	// Services are the details of every service a project of the map lists, once per slug, in slug order.
	Services      []MapService
	Organizations []MapOrganization
}

// MapService is a service of the map as the catalog of NICE describes it. Take it from ServiceMap.Services only:
// CallOperation sends a token of the user to Endpoint.
type MapService struct {
	Slug        string
	Name        string
	Description string
	// Endpoint is the address of the service and BasePath the prefix of its operation paths.
	Endpoint string
	BasePath string
}

// MapOrganization is an organization of the user with the projects where a service may be called.
type MapOrganization struct {
	ID       string
	Name     string
	Slug     string
	Projects []MapProject
	// ProjectsTruncated is true when NICE listed only part of the projects of the organization: the map is then
	// not complete for it.
	ProjectsTruncated bool
}

// MapProject is a project with the slugs of the services the user may call in it.
type MapProject struct {
	ID       string
	Name     string
	Slug     string
	Services []string
}

// ServiceOperations are the operations of one service whose permission the user holds in at least one project.
type ServiceOperations struct {
	// Service is the slug of the service.
	Service string
	// Description is the description of the service in the catalog of NICE; empty when the service has none, and from
	// a NICE that does not send it.
	Description string
	// BusinessDomain is the business domain of the service, e.g. IoT; empty when the service has none, and from a
	// NICE that does not send it.
	BusinessDomain string
	Operations     []ServiceOperation
	// Tags are the tags of the service in the order of its document.
	Tags []OperationTag
	// CatalogVersion grows each time NICE publishes the catalog of the service; 0 from a NICE that does not send it.
	CatalogVersion int64
	// ETag stands for the whole list; pass it to ServiceOperationsIfChanged. Empty from a NICE that does not send it.
	ETag string
}

// ServiceOperation is one operation of a service as its catalog lists it.
type ServiceOperation struct {
	Key     string
	Method  string
	Path    string
	Summary string
	// Description is the description of the operation in the document of the service; empty when it has none.
	Description string
	// Permission is the permission the service asks for the operation.
	Permission string
	Tag        string
	// Sensitive is true when the service checks the caller online for the operation. The SDK does not act on it:
	// whether to ask the user first is the choice of the application.
	Sensitive bool
	// Headers are the headers the client must send; CallOperation sends them.
	Headers []OperationHeader
	// RequestFields name the parameters and the top-level body properties of the operation, never a value.
	RequestFields []RequestField
}

// OperationHeader is a header an operation needs.
type OperationHeader struct {
	Name  string
	Value string
}

// RequestField is the name of one parameter or top-level body property of an operation.
type RequestField struct {
	// Location is path, query, header or body.
	Location string
	Name     string
	Required bool
	// Type is string, integer, number, boolean, array or object; empty when the document of the service does not say.
	Type string
	// Description, Format and Enum are what the document of the service says of the field, empty when it does not.
	Description string
	Format      string
	// Enum holds the allowed values as encoding/json decodes them: string, float64 or bool.
	Enum []any
	// EnumTruncated is true when the document lists more allowed values than Enum holds.
	EnumTruncated bool
}

// OperationTag is a tag of a service.
type OperationTag struct {
	Name        string
	Description string
}

type servicesPage struct {
	Services []struct {
		Slug        string `json:"slug"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Endpoint    string `json:"endpoint"`
		BasePath    string `json:"base_path"`
	} `json:"services"`
	Organizations []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Slug     string `json:"slug"`
		Projects []struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Slug     string   `json:"slug"`
			Services []string `json:"services"`
		} `json:"projects"`
		ProjectsTruncated bool `json:"projects_truncated"`
	} `json:"organizations"`
	Page struct {
		NextPageToken string `json:"next_page_token"`
	} `json:"page"`
}

type operationsBody struct {
	Service        string `json:"service"`
	Description    string `json:"description"`
	BusinessDomain string `json:"business_domain"`
	CatalogVersion int64  `json:"catalog_version,string"`
	Operations     []struct {
		Key         string `json:"key"`
		Method      string `json:"method"`
		Path        string `json:"path"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Permission  string `json:"permission"`
		Tag         string `json:"tag"`
		Sensitive   bool   `json:"sensitive"`
		Headers     []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		RequestFields []struct {
			Location      string `json:"location"`
			Name          string `json:"name"`
			Required      bool   `json:"required"`
			Type          string `json:"type"`
			Description   string `json:"description"`
			Format        string `json:"format"`
			Enum          []any  `json:"enum"`
			EnumTruncated bool   `json:"enum_truncated"`
		} `json:"request_fields"`
	} `json:"operations"`
	Tags []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tags"`
	Page struct {
		NextPageToken string `json:"next_page_token"`
	} `json:"page"`
}

// Services returns the service map of the user of subjectToken, read from GET /api/v1/me/services with the delegated
// token of the NICE API that Contexts uses: one exchange serves Contexts, Services and ServiceOperations of one
// subject token, and the token is exchanged once more when NICE answers 401 token_stale or expired. subjectToken is
// the sign-in token of Client.SignInToken, or a token of the user for the service of this client. NICE lists a
// project when a service other than that of the client is active in it and the user holds a permission of it; the
// service of the client need not be active there.
//
// Every page is read, and a service several pages name is returned once. More than 100 pages, a page larger than
// 4 MiB, or any failure returns an error and no map, never part of it. The errors are those of Contexts. Nothing is
// kept: read the map again to see a change.
func (x *ExchangeClient) Services(ctx context.Context, subjectToken string) (ServiceMap, error) {
	const what = "GET /api/v1/me/services"
	var out ServiceMap
	listed := map[string]bool{}
	pageToken := ""
	for page := 0; page < maxContextsPages; page++ {
		q := url.Values{"page_size": {fmt.Sprint(contextsPageSize)}}
		if pageToken != "" {
			q.Set("page_token", pageToken)
		}
		var p servicesPage
		if _, err := x.niceGet(ctx, subjectToken, what, "/api/v1/me/services?"+q.Encode(), maxContextsBody, nil, &p); err != nil {
			return ServiceMap{}, err
		}
		for _, s := range p.Services {
			if listed[s.Slug] {
				continue
			}
			listed[s.Slug] = true
			out.Services = append(out.Services, MapService{Slug: s.Slug, Name: s.Name, Description: s.Description,
				Endpoint: s.Endpoint, BasePath: s.BasePath})
		}
		for _, o := range p.Organizations {
			org := MapOrganization{ID: o.ID, Name: o.Name, Slug: o.Slug, ProjectsTruncated: o.ProjectsTruncated}
			for _, pr := range o.Projects {
				org.Projects = append(org.Projects, MapProject{ID: pr.ID, Name: pr.Name, Slug: pr.Slug, Services: pr.Services})
			}
			out.Organizations = append(out.Organizations, org)
		}
		if p.Page.NextPageToken == "" {
			sort.SliceStable(out.Services, func(i, j int) bool { return out.Services[i].Slug < out.Services[j].Slug })
			return out, nil
		}
		pageToken = p.Page.NextPageToken
	}
	return ServiceMap{}, fmt.Errorf("niceauth: %s has more than %d pages", what, maxContextsPages)
}

// ServiceOperations returns the operations of the service slug that the user of subjectToken holds the permission
// of, read from GET /api/v1/me/services/{slug}/operations with the delegated token of the NICE API, as Services.
// The operations of a service are the same in every project, so one call serves all of them.
//
// The list is read in pages of 500, following next_page_token, and each page is bounded to 16 MiB. When the list
// changes while it is read (another ETag on a later page, or invalid_page_token), it is read again from the first
// page once; a second change is an error. A NICE without paging answers the whole list at once. An empty slug is
// refused before anything is exchanged or sent. NICE answers 404 not_found, returned as an APIError, for a service the
// user may not call, whatever the reason. The other errors are those of Contexts.
func (x *ExchangeClient) ServiceOperations(ctx context.Context, subjectToken, slug string) (ServiceOperations, error) {
	ops, _, err := x.ServiceOperationsIfChanged(ctx, subjectToken, slug, "")
	return ops, err
}

// ServiceOperationsIfChanged is ServiceOperations on the condition that the list changed since the answer that gave
// etag: it sends etag as If-None-Match with the first page, and returns changed false and no operations when NICE
// answers 304. An empty etag asks without condition, and changed is then true.
func (x *ExchangeClient) ServiceOperationsIfChanged(ctx context.Context, subjectToken, slug, etag string) (ServiceOperations, bool, error) {
	if slug == "" || slug == "." || slug == ".." {
		return ServiceOperations{}, false, errors.New("niceauth: the slug of the service is required")
	}
	for attempt := 0; ; attempt++ {
		ops, changed, err := x.readOperations(ctx, subjectToken, slug, etag)
		if !errors.Is(err, errListChanged) {
			return ops, changed, err
		}
		if attempt > 0 {
			return ServiceOperations{}, false, fmt.Errorf("niceauth: the operations of %s changed twice while they were read", slug)
		}
	}
}

// errListChanged reports that the list of operations changed between two of its pages.
var errListChanged = errors.New("niceauth: the list changed while it was read")

// readOperations reads every page of the operations of slug once.
func (x *ExchangeClient) readOperations(ctx context.Context, subjectToken, slug, etag string) (ServiceOperations, bool, error) {
	const what = "GET /api/v1/me/services/{slug}/operations"
	// The slug is one path segment whatever it holds, so no other path of NICE is asked.
	path := "/api/v1/me/services/" + url.PathEscape(slug) + "/operations"
	paged := true
	var out ServiceOperations
	pageToken := ""
	for page := 0; page < maxOperationsPages; page++ {
		target := path
		if paged {
			q := url.Values{"page_size": {fmt.Sprint(operationsPageSize)}}
			if pageToken != "" {
				q.Set("page_token", pageToken)
			}
			target += "?" + q.Encode()
		}
		header := http.Header{}
		if page == 0 && etag != "" {
			header.Set("If-None-Match", etag)
		}
		var body operationsBody
		ans, err := x.niceGet(ctx, subjectToken, what, target, maxOperationsBody, header, &body)
		var ae *APIError
		switch {
		case err == nil:
		case page == 0 && paged && errors.As(err, &ae) && ae.Status == http.StatusBadRequest && slices.Contains(ae.unknownFields, "page_size"):
			// A NICE before paging refuses page_size; it answers the whole list without it.
			paged = false
			page--
			continue
		case page > 0 && errors.As(err, &ae) && ae.Status == http.StatusBadRequest && ae.Code == "invalid_page_token":
			return ServiceOperations{}, false, errListChanged
		default:
			return ServiceOperations{}, false, err
		}
		if ans.status == http.StatusNotModified {
			return ServiceOperations{}, false, nil
		}
		tag := ans.header.Get("ETag")
		if page == 0 {
			out = ServiceOperations{Service: body.Service, Description: body.Description, BusinessDomain: body.BusinessDomain,
				CatalogVersion: body.CatalogVersion, ETag: tag}
			for _, t := range body.Tags {
				out.Tags = append(out.Tags, OperationTag{Name: t.Name, Description: t.Description})
			}
		} else if tag != out.ETag {
			return ServiceOperations{}, false, errListChanged
		}
		for _, o := range body.Operations {
			op := ServiceOperation{Key: o.Key, Method: o.Method, Path: o.Path, Summary: o.Summary, Description: o.Description,
				Permission: o.Permission, Tag: o.Tag, Sensitive: o.Sensitive}
			for _, h := range o.Headers {
				op.Headers = append(op.Headers, OperationHeader{Name: h.Name, Value: h.Value})
			}
			for _, f := range o.RequestFields {
				op.RequestFields = append(op.RequestFields, RequestField{Location: f.Location, Name: f.Name, Required: f.Required,
					Type: f.Type, Description: f.Description, Format: f.Format, Enum: f.Enum, EnumTruncated: f.EnumTruncated})
			}
			out.Operations = append(out.Operations, op)
		}
		if !paged || body.Page.NextPageToken == "" {
			return out, true, nil
		}
		pageToken = body.Page.NextPageToken
	}
	return ServiceOperations{}, false, fmt.Errorf("niceauth: %s has more than %d pages", what, maxOperationsPages)
}

// niceAnswer is the status and the headers of an answer of the NICE API.
type niceAnswer struct {
	status int
	header http.Header
}

// niceGet reads the JSON answer of one GET of the NICE API into out, with the delegated token of subjectToken and the
// extra headers given. It asks for gzip and bounds the body after it is decompressed. A 304 leaves out untouched.
// what names the operation in an error; pathAndQuery follows the issuer.
func (x *ExchangeClient) niceGet(ctx context.Context, subjectToken, what, pathAndQuery string, maxBody int, header http.Header, out any) (niceAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x.cfg.Issuer+pathAndQuery, nil)
	if err != nil {
		return niceAnswer{}, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	// Set here, so the transport of the application does not decompress it and the bound below applies after it.
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := x.doAs(ctx, subjectToken, Key{Audience: "nice"}, req, x.nice)
	if err != nil {
		var ue *url.Error
		if !IsTemporary(err) && ctx.Err() == nil && errors.As(err, &ue) {
			return niceAnswer{}, &TemporaryError{Err: err}
		}
		return niceAnswer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	ans := niceAnswer{status: resp.StatusCode, header: resp.Header}
	if resp.StatusCode == http.StatusNotModified {
		return ans, nil
	}
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return ans, &TemporaryError{Err: fmt.Errorf("niceauth: %s answered a gzip body that cannot be read: %w", what, err)}
		}
		defer func() { _ = zr.Close() }()
		resp.Body = zr
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ans, apiError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
	if err != nil {
		return ans, &TemporaryError{Err: err}
	}
	if len(raw) > maxBody {
		return ans, fmt.Errorf("niceauth: %s answered a body larger than %d MiB", what, maxBody>>20)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ans, fmt.Errorf("niceauth: %s answered a body that is not its JSON: %w", what, err)
	}
	return ans, nil
}
