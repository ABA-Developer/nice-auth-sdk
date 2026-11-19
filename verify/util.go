package verify

import "encoding/base64"

func base64RawURL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
