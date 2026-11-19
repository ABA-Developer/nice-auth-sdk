package verify_test

import (
	"context"
	"net/http"

	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

// A service verifies the tokens of its callers, guards each operation with the
// permission the OpenAPI document declares, and reads the access change feed.
func Example() {
	ctx := context.Background()

	v, err := verify.New(verify.Config{
		Issuer:   "https://auth.example.com",
		Service:  "navi",
		JWKSFile: "/var/lib/navi/jwks.json", // so a restart while NICE is down still verifies
		// The service decides how an organization becomes a tenant: here, created on first use.
		Tenants: verify.ProvisionOnFirstUse(func(ctx context.Context, org string) error { return createTenant(ctx, org) }),
		// Operations declared x-nice-sensitive are checked online.
		Checker: verify.NewHTTPChecker("https://auth.example.com", "nice_sk_reader.key"),
	})
	if err != nil {
		panic(err)
	}
	go v.Run(ctx) // refresh the JWKS
	if err := v.StartFeed(ctx, verify.FeedConfig{APIKey: "nice_sk_reader.key"}); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /orders", v.Require("navi.orders.read")(http.HandlerFunc(listOrders)))
	mux.Handle("DELETE /orders/{id}", v.Require("navi.orders.delete",
		verify.WithProject(func(r *http.Request) string { return r.Header.Get("X-Project-Id") }),
		verify.Sensitive())(http.HandlerFunc(deleteOrder)))
	_ = http.ListenAndServe(":8080", v.Middleware(mux))
}

func createTenant(context.Context, string) error { return nil }

func listOrders(w http.ResponseWriter, r *http.Request) {
	claims, _ := verify.FromContext(r.Context())       // who is calling, and in which project
	tenant, _ := verify.TenantFromContext(r.Context()) // the tenant of the organization of the token
	_, _, _ = w, claims, tenant
}

func deleteOrder(http.ResponseWriter, *http.Request) {}
