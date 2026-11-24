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

// The feed keys are shared with NICE, which computes them for the changes it records. The expected values were
// computed outside Go, like those of PermsRef.
func TestFeedKeyIsTheHashOfTheLinesInTheirOrder(t *testing.T) {
	for _, tc := range []struct {
		lines []string
		want  string
	}{
		{[]string{"p", "usr_0192f2a0-7d4b-7d3f-9a1c-3b9e4f1a2c10", "org_0192f2a0-7d4b-7d3f-9a1c-3b9e4f1a2c11"}, "v1.o2wpt4uj_fNkyq1KCM2mGFWNvlp4G9--DmBt-_kzktE"},
		{[]string{"j", "prj_0192f2a0-7d4b-7d3f-9a1c-3b9e4f1a2c12"}, "v1.ofVCIXIg8asiIqlR6lDvutW9v_N3qYBhHsbdWChMUoQ"},
		{[]string{"o", "org_0192f2a0-7d4b-7d3f-9a1c-3b9e4f1a2c11"}, "v1.h27C0cLZW2fvgYGA2awA6fJRWqF7Aylf5CsoVlvXPlY"},
	} {
		if got := verify.FeedKey(tc.lines...); got != tc.want {
			t.Errorf("FeedKey(%q) = %q, want %q", tc.lines, got, tc.want)
		}
	}
	org := "org_0192f2a0-7d4b-7d3f-9a1c-3b9e4f1a2c11"
	if verify.FeedKey("o", org) == verify.FeedKey(org, "o") {
		t.Error("the order of the lines is part of the key")
	}
}
