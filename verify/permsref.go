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
	return hashLines(names)
}

// FeedKey returns the key an access change sets in the feed, with the encoding of PermsRef over lines in their
// order: "p", sub, org for a principal in an organization; "j", prj for a project; "o", org for an organization.
// NICE computes the same keys, so the feed names what changed without naming a principal, a project or an
// organization.
func FeedKey(lines ...string) string { return hashLines(lines) }

// hashLines is "v1." followed by the base64url SHA-256, without padding, of lines joined by a newline.
func hashLines(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return permsRefV1 + base64.RawURLEncoding.EncodeToString(sum[:])
}
