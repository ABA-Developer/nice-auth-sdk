package credentials

import (
	"errors"
	"os"
	"strings"
)

// The variables ConfigFromEnv reads.
const (
	envIssuer   = "NICE_ISSUER"     // the public address of NICE
	envSAID     = "NICE_SA_ID"      // the ID of the Service Account (sa_...)
	envSAAPIKey = "NICE_SA_API_KEY" // the API key of the Service Account
)

// ConfigFromEnv reads NICE_ISSUER, NICE_SA_ID and NICE_SA_API_KEY from the
// environment of the process into a Config of Kind KindServiceAccount. It does
// not read a .env file. A variable that is unset or empty is an error that
// names it and never shows a value. Set HTTP, Log, OnSessionEnded or other
// fields on the result before New.
//
// The Config holds the API key: do not print or log it.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		Issuer:       strings.TrimSpace(os.Getenv(envIssuer)),
		ClientID:     strings.TrimSpace(os.Getenv(envSAID)),
		ClientSecret: strings.TrimSpace(os.Getenv(envSAAPIKey)),
		Kind:         KindServiceAccount,
	}
	var missing []string
	for _, v := range []struct{ name, value string }{{envIssuer, cfg.Issuer}, {envSAID, cfg.ClientID}, {envSAAPIKey, cfg.ClientSecret}} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, errors.New("niceauth: " + strings.Join(missing, ", ") + " not set")
	}
	return cfg, nil
}

// NewFromEnv is New with the Config of ConfigFromEnv: a Service Account client
// built from NICE_ISSUER, NICE_SA_ID and NICE_SA_API_KEY. It does not call NICE.
func NewFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg)
}
