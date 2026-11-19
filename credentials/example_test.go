package credentials_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://auth.example.com/api/v1/me/contexts", nil)
	resp, err := x.DoAs(ctx, signIn.Access, credentials.Key{Audience: "nice"}, req)
	if err == nil {
		_ = resp.Body.Close() // the organizations and projects where the user may use the service
	}
}
