package verify_test

import (
	"testing"

	"github.com/ABA-Developer/nice-auth-sdk/verify"
)

// The expected values were computed outside Go: printf '<names joined by \n>' | openssl dgst -sha256 -binary | basenc --base64url.
func TestPermsRefIsTheHashOfTheSortedNames(t *testing.T) {
	const want = "v1.M8akJ-SX6NtB-NmmrCA-029nXXffK7dYwDwxzAq_zao"
	for name, perms := range map[string][]string{
		"sorted":          {"a.y.edit", "b.x.read"},
		"unsorted":        {"b.x.read", "a.y.edit"},
		"with duplicates": {"b.x.read", "a.y.edit", "b.x.read", "a.y.edit"},
	} {
		if got := verify.PermsRef(perms); got != want {
			t.Errorf("%s: PermsRef = %q, want %q", name, got, want)
		}
	}
	if got := verify.PermsRef(nil); got != "v1.47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Errorf("no permission: PermsRef = %q", got)
	}
	if verify.PermsRef([]string{"a.y.edit"}) == want {
		t.Error("another list has another reference")
	}
}

func TestPermsRefLeavesItsArgumentAsItIs(t *testing.T) {
	perms := []string{"b.x.read", "a.y.edit", "b.x.read"}
	verify.PermsRef(perms)
	if perms[0] != "b.x.read" || perms[1] != "a.y.edit" || perms[2] != "b.x.read" {
		t.Fatalf("the caller's slice was reordered: %v", perms)
	}
}
