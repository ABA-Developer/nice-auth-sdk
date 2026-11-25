package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
)

// maxOperationsBody bounds the body of the operations of one service: the 2000 operations a catalog import allows,
// each with its request fields.
const maxOperationsBody = 16 << 20

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
	Service    string
	Operations []ServiceOperation
	// Tags are the tags of the service in the order of its document.
	Tags []OperationTag
}

// ServiceOperation is one operation of a service as its catalog lists it.
type ServiceOperation struct {
	Key     string
	Method  string
	Path    string
	Summary string
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
	Service    string `json:"service"`
	Operations []struct {
		Key        string `json:"key"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		Summary    string `json:"summary"`
		Permission string `json:"permission"`
		Tag        string `json:"tag"`
		Sensitive  bool   `json:"sensitive"`
		Headers    []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		RequestFields []struct {
			Location string `json:"location"`
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Type     string `json:"type"`
		} `json:"request_fields"`
	} `json:"operations"`
	Tags []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tags"`
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
		if err := x.niceGet(ctx, subjectToken, what, "/api/v1/me/services?"+q.Encode(), maxContextsBody, &p); err != nil {
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
// An empty slug is refused before anything is exchanged or sent. NICE answers 404 not_found, returned as an
// APIError, for a service the user may not call, whatever the reason. A body larger than 16 MiB is an error. The
// other errors are those of Contexts.
func (x *ExchangeClient) ServiceOperations(ctx context.Context, subjectToken, slug string) (ServiceOperations, error) {
	if slug == "" || slug == "." || slug == ".." {
		return ServiceOperations{}, errors.New("niceauth: the slug of the service is required")
	}
	var body operationsBody
	// The slug is one path segment whatever it holds, so no other path of NICE is asked.
	err := x.niceGet(ctx, subjectToken, "GET /api/v1/me/services/{slug}/operations",
		"/api/v1/me/services/"+url.PathEscape(slug)+"/operations", maxOperationsBody, &body)
	if err != nil {
		return ServiceOperations{}, err
	}
	out := ServiceOperations{Service: body.Service}
	for _, o := range body.Operations {
		op := ServiceOperation{Key: o.Key, Method: o.Method, Path: o.Path, Summary: o.Summary, Permission: o.Permission,
			Tag: o.Tag, Sensitive: o.Sensitive}
		for _, h := range o.Headers {
			op.Headers = append(op.Headers, OperationHeader{Name: h.Name, Value: h.Value})
		}
		for _, f := range o.RequestFields {
			op.RequestFields = append(op.RequestFields, RequestField{Location: f.Location, Name: f.Name, Required: f.Required, Type: f.Type})
		}
		out.Operations = append(out.Operations, op)
	}
	for _, t := range body.Tags {
		out.Tags = append(out.Tags, OperationTag{Name: t.Name, Description: t.Description})
	}
	return out, nil
}

// niceGet reads the JSON answer of one GET of the NICE API into out, with the delegated token of subjectToken.
// what names the operation in an error; pathAndQuery follows the issuer.
func (x *ExchangeClient) niceGet(ctx context.Context, subjectToken, what, pathAndQuery string, maxBody int, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x.cfg.Issuer+pathAndQuery, nil)
	if err != nil {
		return err
	}
	resp, err := x.doAs(ctx, subjectToken, Key{Audience: "nice"}, req, x.nice)
	if err != nil {
		var ue *url.Error
		if !IsTemporary(err) && ctx.Err() == nil && errors.As(err, &ue) {
			return &TemporaryError{Err: err}
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
	if err != nil {
		return &TemporaryError{Err: err}
	}
	if len(raw) > maxBody {
		return fmt.Errorf("niceauth: %s answered a body larger than %d MiB", what, maxBody>>20)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("niceauth: %s answered a body that is not its JSON: %w", what, err)
	}
	return nil
}
