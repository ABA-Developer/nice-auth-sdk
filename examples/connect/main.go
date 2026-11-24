// Example connect demonstrates a web backend that signs a user in at NICE and
// keeps the refresh token on the server (a backend for a frontend). The browser
// only holds a session cookie; no token ever reaches it.
//
//	NICE_ISSUER         the issuer of NICE
//	NICE_CLIENT_ID      the OAuth client of this application
//	NICE_CLIENT_SECRET  its secret (empty for a public client, which then has no picker)
//	PUBLIC_URL          where the browser reaches this program; default http://localhost:8084.
//	                    PUBLIC_URL + /callback must be a redirect URI of the client.
//	SERVICE_SLUG        the slug of the service to call; default nadi
//	SERVICE_URL         the address of that service
//	TOKEN_DIR           where refresh tokens are kept; default ./tokens
//
// Open PUBLIC_URL in a browser: / shows the state, /login starts the sign-in,
// /contexts lists the organizations and projects of the user to pick one
// (right after the sign-in), /devices calls the service as the signed-in user
// in the picked project, /logout ends the session.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"

	"github.com/ABA-Developer/nice-auth-sdk/credentials"
	"github.com/ABA-Developer/nice-auth-sdk/examples/internal/env"
)

const cookieName = "example_session"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	public := strings.TrimRight(env.Or("PUBLIC_URL", "http://localhost:8084"), "/")
	slug, serviceURL := env.Or("SERVICE_SLUG", "nadi"), env.Must("SERVICE_URL")

	// Refresh tokens are secrets. FileStore keeps them in files only the owner can read, not encrypted: in
	// production implement credentials.Store over your own database and encrypt them.
	store, err := credentials.NewFileStore(env.Or("TOKEN_DIR", "tokens"))
	if err != nil {
		log.Fatal(err)
	}
	client, err := credentials.New(credentials.Config{
		Issuer: env.Must("NICE_ISSUER"), ClientID: env.Must("NICE_CLIENT_ID"), ClientSecret: os.Getenv("NICE_CLIENT_SECRET"),
		Kind: credentials.KindBFF, Store: store,
		OnSessionEnded: func(subject string, err error) {
			// NICE ended the session (signed out elsewhere, access removed): the user must sign in again.
			log.Printf("the NICE session of %s ended: %v", subject, err)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	go client.Run(ctx)

	// The picker needs a confidential client: the exchange for the NICE API is authenticated with the secret of
	// the same service client. A public client has no picker and calls the service where NICE puts the user.
	var exchange *credentials.ExchangeClient
	if secret := os.Getenv("NICE_CLIENT_SECRET"); secret != "" {
		exchange, err = credentials.NewExchange(credentials.ExchangeConfig{
			Issuer: env.Must("NICE_ISSUER"), ClientID: env.Must("NICE_CLIENT_ID"), ClientSecret: secret,
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	// The organization and project each browser session picked. A real application keeps them in its sessions.
	var mu sync.Mutex
	picked := map[string]choice{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		if client.Connected(r.Context(), sid) {
			_, _ = fmt.Fprint(w, "signed in. /contexts picks a project, /devices calls the service, /logout signs out\n")
			return
		}
		_, _ = fmt.Fprint(w, "not signed in. open /login\n")
	})

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		// The state and the PKCE verifier are kept by the SDK until the callback. Session binds the callback to
		// this browser, so nobody can finish a sign-in that another browser started. This example has no users
		// of its own, so the session ID is also the subject the tokens are kept under.
		authURL, err := client.AuthorizeURL(r.Context(), credentials.ConnectRequest{
			Subject: sid, Session: sid, RedirectURI: public + "/callback", Audience: slug,
		})
		if err != nil {
			http.Error(w, "cannot start the sign-in", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		conn, err := client.HandleCallback(r.Context(), session(w, r), r.URL.Query())
		switch {
		case errors.Is(err, credentials.ErrStateMismatch):
			http.Error(w, "this sign-in was not started in this browser, or it expired", http.StatusBadRequest)
			return
		case err != nil:
			http.Error(w, "the sign-in failed", http.StatusBadGateway)
			return
		}
		// conn.NiceSubject is the NICE account (usr_...). An application with users of its own links it to its
		// user here and refuses an account that is already linked to another user.
		log.Printf("signed in as %s", conn.NiceSubject)
		http.Redirect(w, r, "/contexts", http.StatusFound)
	})

	mux.HandleFunc("GET /contexts", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		if exchange == nil {
			_, _ = fmt.Fprint(w, "no picker: a public client cannot exchange tokens. /devices calls the service\n")
			return
		}
		// The sign-in token works before any project is known, and only for the NICE API.
		signIn, err := client.SignInToken(r.Context(), sid)
		if errors.Is(err, credentials.ErrNotConnected) || errors.Is(err, credentials.ErrSessionEnded) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if err != nil {
			http.Error(w, "NICE cannot be reached now", http.StatusBadGateway)
			return
		}
		contexts, err := exchange.Contexts(r.Context(), signIn.Access)
		if err != nil {
			http.Error(w, "the organizations cannot be read now", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pickerPage.Execute(w, picker(contexts, slug)); err != nil {
			log.Print(err)
		}
	})

	mux.HandleFunc("GET /choose", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		// No need to check the pair against the list: NICE refuses a token for a context the user may not use.
		mu.Lock()
		picked[sid] = choice{Org: r.URL.Query().Get("org"), Project: r.URL.Query().Get("project")}
		mu.Unlock()
		http.Redirect(w, r, "/devices", http.StatusFound)
	})

	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, serviceURL+"/devices", nil)
		if err != nil {
			http.Error(w, "bad service address", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		c := picked[sid]
		mu.Unlock()
		// Do gets a token for this user and this service with the refresh token, keeps it, and renews it. The
		// picked organization and project are named on every call; empty ones keep those NICE puts the user in.
		resp, err := client.Do(r.Context(), credentials.Key{Subject: sid, Org: c.Org, Audience: slug, Project: c.Project}, req)
		var grant *credentials.GrantError
		switch {
		case errors.Is(err, credentials.ErrNotConnected), errors.Is(err, credentials.ErrSessionEnded):
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		case errors.As(err, &grant):
			// access_denied or invalid_scope: not usable in this context; the session still works.
			http.Error(w, "the service is not available in this context ("+grant.Code+"), pick another at /contexts", http.StatusForbidden)
			return
		case err != nil:
			http.Error(w, "the service cannot be called now", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
	})

	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		// Disconnect revokes the refresh token at NICE. When NICE cannot be reached it returns the error and
		// keeps the session, so the user never looks signed out while the token still works.
		if err := client.Disconnect(r.Context(), session(w, r)); err != nil {
			http.Error(w, "cannot sign out now, try again", http.StatusBadGateway)
			return
		}
		mu.Lock()
		delete(picked, session(w, r))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
		_, _ = fmt.Fprint(w, "signed out\n")
	})

	addr := env.Or("LISTEN_ADDR", "127.0.0.1:8084")
	log.Printf("open %s", public)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type choice struct{ Org, Project string }

type pickerOrg struct {
	Name, ID  string
	ActAs     bool
	Truncated bool
	OrgLevel  bool // the service is used in the organization itself (organization tenancy)
	Projects  []credentials.ContextProject
}

// picker keeps the places where the user may use the service slug, in the order NICE gave them.
func picker(contexts credentials.Contexts, slug string) []pickerOrg {
	var out []pickerOrg
	for _, o := range contexts.Organizations {
		po := pickerOrg{Name: o.Name, ID: o.ID, ActAs: o.ActAs, Truncated: o.ProjectsTruncated, OrgLevel: slices.Contains(o.Services, slug)}
		for _, p := range o.Projects {
			if slices.Contains(p.Services, slug) {
				po.Projects = append(po.Projects, p)
			}
		}
		if po.OrgLevel || len(po.Projects) > 0 {
			out = append(out, po)
		}
	}
	return out
}

// html/template escapes the names, which NICE takes from its users.
var pickerPage = template.Must(template.New("picker").Parse(`<!doctype html>
<title>Pick a project</title>
<h1>Where do you work?</h1>
{{range .}}<h2>{{.Name}}{{if .ActAs}} (acting as operator){{end}}</h2>
<ul>
{{if .OrgLevel}}<li><a href="/choose?org={{.ID}}">the whole organization</a></li>{{end}}
{{$org := .ID}}{{range .Projects}}<li><a href="/choose?org={{$org}}&amp;project={{.ID}}">{{.Name}}</a></li>
{{end}}{{if .Truncated}}<li>more projects exist than NICE listed</li>{{end}}
</ul>
{{else}}<p>The service is not available to you in any organization.</p>
{{end}}`))

// session returns the ID of the browser session, creating the cookie when there is none. A real application
// uses its own session store, and sets Secure on the cookie when it is served over https.
func session(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil && len(c.Value) == 32 {
		return c.Value
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	id := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return id
}
