package credentials_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ABA-Developer/nice-auth-sdk/credentials"
)

// An integration proves the API key of its Service Account and calls a service.
func Example_serviceAccount() {
	ctx := context.Background()
	c, err := credentials.New(credentials.Config{
		Issuer:       "https://auth.example.com",
		ClientID:     "sa_01a17b4e-2222-7000-8000-000000000002",
		ClientSecret: "nice_sk_xxx.yyy", // sent to NICE only, never to a service
		Kind:         credentials.KindServiceAccount,
		OnSessionEnded: func(subject string, err error) {
			// The key was revoked or is wrong: the SDK stopped trying, replace the key and call Reset.
		},
	})
	if err != nil {
		panic(err)
	}
	go c.Run(ctx) // renew the tokens in use

	req, _ := http.NewRequest(http.MethodGet, "https://navi.example.com/orders", nil)
	// Do adds the token and, on 401 token_stale, renews it and sends the request once more.
	resp, err := c.Do(ctx, credentials.Key{Audience: "navi", Project: "prj_01a17b4d-60ec-7555-853c-3e3a50f76435"}, req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// A Service Account takes its ID and API key from the environment (NICE_ISSUER, NICE_SA_ID, NICE_SA_API_KEY) and
// calls a service with a plain *http.Client.
func Example_fromEnv() {
	ctx := context.Background()
	c, err := credentials.NewFromEnv()
	if err != nil {
		panic(err) // names the variable that is not set
	}
	go c.Run(ctx)

	// One client per service: it sends the token to that service only, and refuses any other host.
	hc, err := c.HTTPClient(credentials.Key{Audience: "nadi"}, "https://nadi.example.com")
	if err != nil {
		panic(err) // the address is not https
	}
	resp, err := hc.Get("https://nadi.example.com/devices")
	if err == nil {
		_ = resp.Body.Close()
	}
}

// A client made by a generator or another library takes the token through its transport.
func Example_transport() {
	cfg, err := credentials.ConfigFromEnv()
	if err != nil {
		panic(err)
	}
	cfg.OnSessionEnded = func(subject string, err error) {
		// The API key was revoked: replace it and call Reset.
	}
	c, err := credentials.New(cfg)
	if err != nil {
		panic(err)
	}
	go c.Run(context.Background())

	// base is the transport of the library; nil uses the one of Config.HTTP.
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt, err := c.Transport(credentials.Key{Audience: "nadi"}, "https://nadi.example.com", base)
	if err != nil {
		panic(err)
	}
	hc := &http.Client{Transport: rt}
	_ = hc // hand it to the generated client of nadi
}

// An application with its own sign-in lets a user connect a NICE account when a page needs it.
func Example_connect() {
	ctx := context.Background()
	store, _ := credentials.NewFileStore("/var/lib/app/nice") // refresh tokens: protect this directory
	c, err := credentials.New(credentials.Config{
		Issuer: "https://auth.example.com", ClientID: "cli_console", Kind: credentials.KindBFF, Store: store,
	})
	if err != nil {
		panic(err)
	}

	// "Connect NICE" button: send the browser to NICE. The local session binds the state.
	authURL, _ := c.AuthorizeURL(ctx, credentials.ConnectRequest{
		Subject: "local-user-42", Session: "session-id-of-this-browser",
		RedirectURI: "https://app.example.com/nice/callback", Audience: "navi", Project: "prj_01a17b4d-60ec-7555-853c-3e3a50f76435",
	})
	_ = authURL

	// The callback: the same local session completes it. Keep one NICE account for one local user.
	conn, err := c.HandleCallback(ctx, "session-id-of-this-browser", url.Values{"code": {"..."}, "state": {"..."}})
	if err == nil {
		_ = conn.NiceSubject
	}

	// Another service later: no new sign-in, the refresh token is used.
	_, _ = c.Token(ctx, credentials.Key{Subject: "local-user-42", Audience: "nadi", Project: "prj_01a17b4d-60ec-7555-853c-3e3a50f76435"})

	// "Disconnect" button.
	_ = c.Disconnect(ctx, "local-user-42")
}

// A backend for a browser app (BFF) keeps the refresh tokens of its users and moves a user to another
// organization with no redirect. It keeps the active organization in the user's session and names it on
// every call, so two requests of one user for two organizations each get a token of their own.
func Example_switchOrganization() {
	ctx := context.Background()
	store, _ := credentials.NewFileStore("/var/lib/app/nice") // the Store must keep tokens apart per Key.Org
	c, err := credentials.New(credentials.Config{
		Issuer: "https://auth.example.com", ClientID: "navi-dashboard", ClientSecret: "client-secret", Kind: credentials.KindBFF, Store: store,
		// Sent with the sign-in and again with every refresh; the client must be allowed each of them.
		BaseScopes: []string{"openid", "profile", "email", "offline_access"},
	})
	if err != nil {
		panic(err)
	}
	go c.Run(ctx)

	http.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		// The active organization and project of this browser session, chosen by the user.
		user, org, project := "local-user-42", "org_01a17b4e-1111-7000-8000-000000000001", "prj_01a17b4d-60ec-7555-853c-3e3a50f76435"
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://navi.example.com/orders", nil)
		resp, err := c.Do(r.Context(), credentials.Key{Subject: user, Org: org, Audience: "navi", Project: project}, req)
		var ge *credentials.GrantError
		switch {
		case errors.As(err, &ge) && !ge.Permanent:
			// access_denied or invalid_scope: the user may not use this organization now. The session and
			// the other organizations still work; keep the one before and reload the list of contexts.
			http.Error(w, "this organization is not available", http.StatusForbidden)
			return
		case err != nil:
			http.Error(w, "NICE is not available", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
	})
}

// The backend of a service calls another service, or the NICE API, on behalf of the user whose request it serves:
// it exchanges the token that request brought instead of passing it on.
func Example_exchange() {
	x, err := credentials.NewExchange(credentials.ExchangeConfig{
		Issuer:       "https://auth.example.com",
		ClientID:     "naia-backend",  // the confidential service client of the backend
		ClientSecret: "client-secret", // sent to NICE only
	})
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		// The token of the user, already verified by this service with verify.
		subject := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://nadi.example.com/reports", nil)
		// Org and Project left empty keep those of the user's token; name them to act elsewhere.
		resp, err := x.DoAs(r.Context(), subject, credentials.Key{Audience: "nadi"}, req)
		if err != nil {
			http.Error(w, "nadi is not available for this user", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
	})
}

// The backend of a service client fills a picker of organizations and projects from NICE right after the user
// signed in, before any project is known: it trades the sign-in token for a delegated token of the NICE API.
func Example_discoverContexts() {
	ctx := context.Background()
	c, err := credentials.New(credentials.Config{
		Issuer: "https://auth.example.com", ClientID: "naia-web", ClientSecret: "client-secret", Kind: credentials.KindBFF,
	})
	if err != nil {
		panic(err)
	}
	x, err := credentials.NewExchange(credentials.ExchangeConfig{
		Issuer: "https://auth.example.com", ClientID: "naia-web", ClientSecret: "client-secret", // the same service client
	})
	if err != nil {
		panic(err)
	}

	// A refresh with the base scopes only: a token for the client itself, in the organization of the refresh token.
	signIn, err := c.SignInToken(ctx, "local-user-42")
	if err != nil {
		return // invalid_grant: the session ended, sign the user in again
	}
	contexts, err := x.Contexts(ctx, signIn.Access)
	if err != nil {
		return
	}
	// Show the projects where the user may use naia; the user picks one, kept in the session.
	var org, project string
	for _, o := range contexts.Organizations {
		for _, p := range o.Projects {
			if slices.Contains(p.Services, "naia") && project == "" {
				org, project = o.ID, p.ID
			}
		}
	}
	_, _ = c.Token(ctx, credentials.Key{Subject: "local-user-42", Org: org, Audience: "naia", Project: project})
}

// The backend of a service lists the organizations and projects of the user whose request it serves, with the token
// that request brought.
func ExampleExchangeClient_Contexts() {
	x, err := credentials.NewExchange(credentials.ExchangeConfig{
		Issuer: "https://auth.example.com", ClientID: "naia-backend", ClientSecret: "client-secret",
	})
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/contexts", func(w http.ResponseWriter, r *http.Request) {
		// The token of the user, already verified by this service with verify.
		subject := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		contexts, err := x.Contexts(r.Context(), subject)
		var api *credentials.APIError
		switch {
		case errors.As(err, &api) && api.Code == "user_required":
			http.Error(w, "only a user has contexts", http.StatusForbidden)
			return
		case credentials.IsTemporary(err):
			http.Error(w, "NICE is not available", http.StatusServiceUnavailable)
			return
		case err != nil:
			http.Error(w, "the contexts cannot be read", http.StatusBadGateway)
			return
		}
		for _, o := range contexts.Organizations {
			// o.ActAs marks an organization a platform operator acts as; o.ProjectsTruncated a partial project list.
			for _, p := range o.Projects {
				_, _ = fmt.Fprintf(w, "%s / %s: %v\n", o.Name, p.Name, p.Services)
			}
		}
	})
}

// The backend of an agent learns, right after the user signed in, which other services the user may call and in
// which projects, and loads the operations of a service only when a prompt needs it.
func ExampleExchangeClient_Services() {
	ctx := context.Background()
	c, err := credentials.New(credentials.Config{
		Issuer: "https://auth.example.com", ClientID: "naia-web", ClientSecret: "client-secret", Kind: credentials.KindBFF,
	})
	if err != nil {
		panic(err)
	}
	x, err := credentials.NewExchange(credentials.ExchangeConfig{
		Issuer: "https://auth.example.com", ClientID: "naia-web", ClientSecret: "client-secret", // the same service client
	})
	if err != nil {
		panic(err)
	}

	signIn, err := c.SignInToken(ctx, "local-user-42")
	if err != nil {
		return // invalid_grant: the session ended, sign the user in again
	}
	// One read per session: the map is small. Nothing is kept by the SDK; read it again to see a change.
	services, err := x.Services(ctx, signIn.Access)
	if err != nil {
		return
	}
	for _, o := range services.Organizations {
		// o.ProjectsTruncated: NICE listed only part of the projects, so an answer over "every location" of this
		// organization would not be complete.
		for _, p := range o.Projects {
			fmt.Printf("%s / %s: %v\n", o.Name, p.Name, p.Services) // Hermina / Lokasi A: [nadi]
		}
	}

	// When a prompt needs nadi: its operations are the same in every project, so one read serves all locations.
	ops, err := x.ServiceOperations(ctx, signIn.Access, "nadi")
	var api *credentials.APIError
	switch {
	case errors.As(err, &api) && api.Code == "not_found":
		return // the user may not call nadi anywhere
	case err != nil:
		return
	}
	for _, op := range ops.Operations {
		// op.Key, op.Method, op.Path, op.Summary, op.RequestFields: what a tool definition is built from.
		// op.Sensitive: ask the user before calling it, if the application wants that.
		_ = op
	}
}

// The backend of an agent answers "how many devices in locations A, B and C": one call of the same operation per
// project, each with a token of its own project.
func ExampleExchangeClient_CallOperation() {
	ctx := context.Background()
	c, err := credentials.New(credentials.Config{
		Issuer: "https://auth.example.com", ClientID: "naia-web", ClientSecret: "client-secret", Kind: credentials.KindBFF,
	})
	if err != nil {
		panic(err)
	}
	x, err := credentials.NewExchange(credentials.ExchangeConfig{
		Issuer: "https://auth.example.com", ClientID: "naia-web", ClientSecret: "client-secret",
	})
	if err != nil {
		panic(err)
	}
	// From Services and ServiceOperations, read with the sign-in token; never from the input of a user or a model.
	var nadi credentials.MapService
	var listDevices, getDevice credentials.ServiceOperation

	// The subject of the calls is a token of the user for the service of this client (naia), in a project where
	// naia is active: one of the projects Contexts lists. The sign-in token is refused here (invalid_grant).
	subject, err := c.Token(ctx, credentials.Key{Subject: "local-user-42", Audience: "naia", Project: "prj_01a17b4d-0000-7000-8000-0000000000p0"})
	if err != nil {
		return
	}

	org := "org_01a17b49-56bc-7632-a32f-d47311c068c1" // Hermina
	for _, project := range []string{"prj_01a17b49-56bc-7632-a32f-0000000000a1", "prj_01a17b49-56bc-7632-a32f-0000000000b2"} {
		resp, err := x.CallOperation(ctx, subject.Access, credentials.OperationCall{
			Service: nadi, Operation: listDevices, Org: org, Project: project,
			Query: url.Values{"status": {"active"}},
		})
		var grant *credentials.GrantError
		switch {
		case errors.As(err, &grant):
			continue // NICE refused the exchange: the user may not use nadi in this project now
		case errors.Is(err, credentials.ErrInvalidOperationCall):
			continue // the call was not sent: a path parameter is missing or is not one plain segment
		case err != nil:
			continue // NICE or nadi cannot be reached: report this location as failed
		}
		// The answer of nadi as it is: 200, or 403 when a permission is missing, or 503 to try again later.
		_ = resp.Body.Close()
	}

	// A path parameter, often from a model: the SDK sends it as one escaped segment or refuses the call.
	resp, err := x.CallOperation(ctx, subject.Access, credentials.OperationCall{
		Service: nadi, Operation: getDevice, Org: org, Project: "prj_01a17b49-56bc-7632-a32f-0000000000a1",
		PathParams: map[string]string{"id": "dev 01"}, // GET <endpoint><base path>/devices/dev%2001
	})
	if err == nil {
		_ = resp.Body.Close()
	}
}

// "Switch account" and "Sign out" of an application whose users sign in with NICE. Disconnect comes first in both:
// it revokes the refresh token from the server, whether or not the browser still has a NICE session.
func Example_signOutAndSwitchAccount() {
	c, err := credentials.New(credentials.Config{
		Issuer: "https://auth.example.com", ClientID: "nadi-web", ClientSecret: "client-secret", Kind: credentials.KindBFF,
	})
	if err != nil {
		panic(err)
	}
	// The local user and session of the browser, and the ID token kept from Connection.IDToken, on the server.
	user, session, idToken := "local-user-42", "session-id-of-this-browser", "eyJ..."

	http.HandleFunc("/switch-account", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Disconnect(r.Context(), user); err != nil {
			http.Error(w, "cannot sign out now, try again", http.StatusBadGateway)
			return
		}
		// End the local session here. NICE keeps its session and shows its account chooser.
		authURL, err := c.AuthorizeURL(r.Context(), credentials.ConnectRequest{
			Subject: user, Session: session, RedirectURI: "https://nadi.example.com/auth/callback",
			Prompt: credentials.PromptSelectAccount,
		})
		if err != nil {
			http.Error(w, "cannot start the sign-in", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Disconnect(r.Context(), user); err != nil {
			http.Error(w, "cannot sign out now, try again", http.StatusBadGateway)
			return
		}
		// End the local session here, then NICE ends its own: the next sign-in asks for the password.
		endURL, err := c.EndSessionURL(credentials.EndSessionRequest{
			PostLogoutRedirectURI: "https://nadi.example.com/signed-out", // registered with the OAuth client
			IDTokenHint:           idToken,                               // optional
		})
		if err != nil {
			http.Error(w, "cannot sign out", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, endURL, http.StatusFound)
	})
}
