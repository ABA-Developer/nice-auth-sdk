package verify

// ClaimsWithToken returns c as Verify returns it after reading it from token, for the tests of the callers of NICE
// that forward the token.
func ClaimsWithToken(c Claims, token string) *Claims {
	c.token = &token
	return &c
}
