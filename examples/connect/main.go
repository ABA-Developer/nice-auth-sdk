// Example connect demonstrates a web backend that signs a user in at NICE and
// keeps the refresh token on the server (a backend for a frontend). The browser
// only holds a session cookie; no token ever reaches it.
//
//	NICE_ISSUER         the issuer of NICE
//	NICE_CLIENT_ID      the OAuth client of this application
//	NICE_CLIENT_SECRET  its secret (empty for a public client)
//	PUBLIC_URL          where the browser reaches this program; default http://localhost:8084.
//	                    PUBLIC_URL + /callback must be a redirect URI of the client.
//	SERVICE_SLUG        the slug of the service to call; default nadi
//	SERVICE_URL         the address of that service
//	TOKEN_DIR           where refresh tokens are kept; default ./tokens
//
// Open PUBLIC_URL in a browser: / shows the state, /login starts the sign-in,
// /devices calls the service as the signed-in user, /logout ends the session.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		if client.Connected(r.Context(), sid) {
			_, _ = fmt.Fprint(w, "signed in. /devices calls the service, /logout signs out\n")
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
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		sid := session(w, r)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, serviceURL+"/devices", nil)
		if err != nil {
			http.Error(w, "bad service address", http.StatusInternalServerError)
			return
		}
		// Do gets a token for this user and this service with the refresh token, keeps it, and renews it. A
		// backend whose users switch organizations names Key.Org and Key.Project on every call.
		resp, err := client.Do(r.Context(), credentials.Key{Subject: sid, Audience: slug}, req)
		switch {
		case errors.Is(err, credentials.ErrNotConnected), errors.Is(err, credentials.ErrSessionEnded):
			http.Redirect(w, r, "/login", http.StatusFound)
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
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
		_, _ = fmt.Fprint(w, "signed out\n")
	})

	addr := env.Or("LISTEN_ADDR", "127.0.0.1:8084")
	log.Printf("open %s", public)
	log.Fatal(http.ListenAndServe(addr, mux))
}

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
