package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
)

// permsRefV1 is the version prefix of the only reference format this package knows.
const permsRefV1 = "v1."

// PermsRef returns the reference of a permission list, as the perms_ref claim carries it: "v1." followed by the
// base64url SHA-256, without padding, of the names sorted by byte, without duplicates, joined by a newline.
func PermsRef(permissions []string) string {
	names := slices.Clone(permissions)
	slices.Sort(names)
	names = slices.Compact(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return permsRefV1 + base64.RawURLEncoding.EncodeToString(sum[:])
}
