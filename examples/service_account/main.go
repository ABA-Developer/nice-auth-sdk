// Example service_account demonstrates a machine caller: a program that proves
// the API key of its Service Account to NICE and calls a service with the token
// it gets.
//
//	NICE_ISSUER      the address of NICE, e.g. https://auth.example.com
//	NICE_SA_ID       the ID of the Service Account (sa_...)
//	NICE_SA_API_KEY  its API key
//	SERVICE_SLUG     the slug of the service to call, e.g. nadi
//	SERVICE_URL      the address of that service, e.g. https://nadi.example.com
//	SERVICE_PATH     the path to read; default /devices
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/ABA-Developer/nice-auth-sdk/credentials"
	"github.com/ABA-Developer/nice-auth-sdk/examples/internal/env"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// ConfigFromEnv reads NICE_ISSUER, NICE_SA_ID and NICE_SA_API_KEY. NewFromEnv does the same in one call; the
	// Config is taken here to set OnSessionEnded.
	cfg, err := credentials.ConfigFromEnv()
	if err != nil {
		log.Fatal(err) // names the variable that is not set, never its value
	}
	cfg.OnSessionEnded = func(subject string, err error) {
		// NICE refused the key for good (revoked, expired, wrong). The SDK stopped asking; alert the operator.
		log.Printf("the API key of %s no longer works: %v", subject, err)
	}
	client, err := credentials.New(cfg)
	if err != nil {
		log.Fatal(err) // e.g. NICE_ISSUER is plain http and not loopback
	}
	// Run renews the tokens in use in the background. A short program can leave it out: Token renews on demand.
	go client.Run(ctx)

	// One *http.Client per service. It adds the token of the key to every request, renews a stale token once, and
	// refuses to send the token to any other host than the service.
	service := env.Must("SERVICE_URL")
	hc, err := client.HTTPClient(credentials.Key{Audience: env.Must("SERVICE_SLUG")}, service)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := hc.Get(service + env.Or("SERVICE_PATH", "/devices"))
	if err != nil {
		log.Fatal(explain(err))
	}
	defer func() { _ = resp.Body.Close() }()
	fmt.Println(resp.Status)
	_, _ = io.Copy(os.Stdout, io.LimitReader(resp.Body, 1<<20))

	// A 403 is an answer of the service, not an error of the SDK: the Service Account lacks the permission.
	if resp.StatusCode == http.StatusForbidden {
		log.Print("the Service Account has no role that grants this operation")
	}
}

// explain tells the failures of the SDK apart. http.Client wraps them in a *url.Error; errors.As sees through it.
func explain(err error) string {
	var grant *credentials.GrantError
	switch {
	case errors.As(err, &grant) && grant.Permanent:
		return "NICE refused the API key for good; replace the key: " + grant.Code
	case errors.As(err, &grant):
		return "NICE refused this request: " + grant.Code + " " + grant.Description
	case credentials.IsTemporary(err):
		return "NICE cannot be reached; try again later"
	case errors.Is(err, credentials.ErrForeignHost):
		return "the request is not for the service this client was made for"
	}
	return "the service cannot be reached: " + err.Error()
}
