package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	// contextsPageSize is the largest page NICE serves.
	contextsPageSize = 50
	// maxContextsPages bounds the pages read: 5000 organizations at most.
	maxContextsPages = 100
	// maxContextsBody bounds the body of one page.
	maxContextsBody = 4 << 20
	// maxErrorBody bounds what is read of an error answer.
	maxErrorBody = 64 << 10
)

// Contexts are where the user of a subject token may work, as NICE lists them: the organizations in the order NICE
// gives (where the user signed in first, then those an operator acts as), each with its projects.
type Contexts struct {
	// CurrentOrganization is the organization of the subject token.
	CurrentOrganization string
	// Services are the slugs of the services the list covers.
	Services      []string
	Organizations []ContextOrganization
}

// ContextOrganization is an organization of the user.
type ContextOrganization struct {
	ID   string
	Name string
	Slug string
	// ActAs is true for an organization a platform operator may act as without being a member of it.
	ActAs bool
	// Services are the services the user may use in the organization itself, without a project (organization
	// tenancy). Empty until NICE sends it.
	Services []string
	Projects []ContextProject
	// ProjectsTruncated is true when NICE listed only part of the projects of the organization.
	ProjectsTruncated bool
}

// ContextProject is a project of an organization with the services the user may use in it.
type ContextProject struct {
	ID       string
	Name     string
	Slug     string
	Services []string
}

type contextsPage struct {
	CurrentOrganizationID string   `json:"current_organization_id"`
	Services              []string `json:"services"`
	Organizations         []struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Slug     string   `json:"slug"`
		ActAs    bool     `json:"act_as"`
		Services []string `json:"services"`
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

// Contexts returns the organizations and projects of the user of subjectToken, read from GET /api/v1/me/contexts
// with a delegated token of the NICE API: the token Token gives for Key{Audience: "nice"}, kept per subject token as
// for DoAs, and exchanged once more when NICE answers 401 token_stale or expired. subjectToken is the sign-in token
// of Client.SignInToken in a backend that holds the user's refresh token, or the verified token of the request in
// the backend of a service. A public client (a SPA) cannot use it: the exchange needs the secret of a confidential
// service client.
//
// Every page is read. More than 100 pages, a page larger than 4 MiB, or any failure returns an error and no
// contexts, never part of the list. A refusal of the exchange is returned as a GrantError; an answer of NICE other
// than 2xx as an APIError, wrapped in a TemporaryError for a 5xx or 429; a failure to reach NICE as a
// TemporaryError. NICE is called with no redirect followed.
func (x *ExchangeClient) Contexts(ctx context.Context, subjectToken string) (Contexts, error) {
	var out Contexts
	pageToken := ""
	for page := 0; page < maxContextsPages; page++ {
		p, err := x.contextsPage(ctx, subjectToken, pageToken)
		if err != nil {
			return Contexts{}, err
		}
		if page == 0 {
			out.CurrentOrganization, out.Services = p.CurrentOrganizationID, p.Services
		}
		for _, o := range p.Organizations {
			org := ContextOrganization{ID: o.ID, Name: o.Name, Slug: o.Slug, ActAs: o.ActAs, Services: o.Services,
				ProjectsTruncated: o.ProjectsTruncated}
			for _, pr := range o.Projects {
				org.Projects = append(org.Projects, ContextProject{ID: pr.ID, Name: pr.Name, Slug: pr.Slug, Services: pr.Services})
			}
			out.Organizations = append(out.Organizations, org)
		}
		if p.Page.NextPageToken == "" {
			return out, nil
		}
		pageToken = p.Page.NextPageToken
	}
	return Contexts{}, fmt.Errorf("niceauth: GET /api/v1/me/contexts has more than %d pages", maxContextsPages)
}

func (x *ExchangeClient) contextsPage(ctx context.Context, subjectToken, pageToken string) (contextsPage, error) {
	q := url.Values{"page_size": {fmt.Sprint(contextsPageSize)}}
	if pageToken != "" {
		q.Set("page_token", pageToken)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x.cfg.Issuer+"/api/v1/me/contexts?"+q.Encode(), nil)
	if err != nil {
		return contextsPage{}, err
	}
	resp, err := x.doAs(ctx, subjectToken, Key{Audience: "nice"}, req, x.nice)
	if err != nil {
		var ue *url.Error
		if !IsTemporary(err) && ctx.Err() == nil && errors.As(err, &ue) {
			return contextsPage{}, &TemporaryError{Err: err}
		}
		return contextsPage{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return contextsPage{}, apiError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxContextsBody+1))
	if err != nil {
		return contextsPage{}, &TemporaryError{Err: err}
	}
	if len(raw) > maxContextsBody {
		return contextsPage{}, fmt.Errorf("niceauth: a page of GET /api/v1/me/contexts is larger than %d MiB", maxContextsBody>>20)
	}
	var p contextsPage
	if err := json.Unmarshal(raw, &p); err != nil {
		return contextsPage{}, fmt.Errorf("niceauth: GET /api/v1/me/contexts answered a body that is not its JSON: %w", err)
	}
	return p, nil
}

// apiError reads the error answer of the NICE API. The raw body is never kept: only the fields NICE sets.
func apiError(resp *http.Response) error {
	e := &APIError{Status: resp.StatusCode}
	if isRedirect(resp.StatusCode) {
		e.Code = "redirect"
		e.Message = "NICE answered with a redirect to " + redirectTarget(resp) + "; it was not followed, check Issuer"
		return e
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var body struct {
		Code      string `json:"error_code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(raw, &body) == nil {
		e.Code, e.Message, e.RequestID = body.Code, body.Message, body.RequestID
	}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &TemporaryError{Err: e}
	}
	return e
}
