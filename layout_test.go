package niceauth

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	module      = "github.com/ABA-Developer/nice-auth-sdk"
	credentials = module + "/credentials"
	verify      = module + "/verify"
	examples    = module + "/examples"
	jose        = "github.com/go-jose/go-jose/v4"
)

// The two sides of the SDK stay apart: a service that only verifies tokens must not carry the caller side, and
// verify needs nothing beyond the standard library and go-jose. Neither side depends on the examples.
func TestTheTwoSidesStayApart(t *testing.T) {
	for _, file := range sources(t, "verify") {
		for _, p := range imports(t, file) {
			switch {
			case under(p, credentials):
				t.Errorf("%s imports %s: verify must not import credentials", file, p)
			case under(p, examples):
				t.Errorf("%s imports %s: the SDK must not import its examples", file, p)
			case !isStdlib(p) && !under(p, jose) && !under(p, verify):
				t.Errorf("%s imports %s: verify may import only the standard library and go-jose", file, p)
			}
		}
	}
	for _, file := range sources(t, "credentials") {
		for _, p := range imports(t, file) {
			switch {
			case under(p, verify):
				t.Errorf("%s imports %s: credentials must not import verify", file, p)
			case under(p, examples):
				t.Errorf("%s imports %s: the SDK must not import its examples", file, p)
			}
		}
	}
}

func under(path, prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }

// isStdlib reports whether an import path belongs to the standard library: its first element has no dot.
func isStdlib(p string) bool {
	first, _, _ := strings.Cut(p, "/")
	return !strings.Contains(first, ".")
}

// sources lists the Go files of dir, tests included: a test that imports the other side would hide a real need.
func sources(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no source found under %s", dir)
	}
	return out
}

func imports(t *testing.T, file string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		out = append(out, strings.Trim(imp.Path.Value, `"`))
	}
	return out
}
