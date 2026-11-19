package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestSafeNamesEveryStringApart(t *testing.T) {
	pairs := [][2]string{
		{"bob.example", "bobˮxample"}, // v0.1.0 named both bob~2eexample
		{"a.b", "a˫"},
		{"alice@corp.id", "aliceЌorp.id"},
		{"a\xff", "a\xfe"}, // invalid UTF-8 used to collapse to U+FFFD
		{"a\xff", "a�"},
		{"\x01f", "\x1f"},
		{"a.2eb", "a.b"}, // the escape character itself is escaped
	}
	for _, p := range pairs {
		if safe(p[0]) == safe(p[1]) {
			t.Errorf("%q and %q share the name %q", p[0], p[1], safe(p[0]))
		}
	}
}

func TestSafeKeepsSimpleNamesAndWritesNoSeparator(t *testing.T) {
	for _, s := range []string{"usr_123-abc", "sa_01a1f353-eb8f-7a84-90f6-81565132582d", "nadi", "prj_a"} {
		if got := safe(s); got != s {
			t.Errorf("safe(%q) = %q; a simple name keeps its v0.1.0 file", s, got)
		}
	}
	for _, s := range []string{"a b/c\\d+e*f?g[h]i~j", "../../etc/passwd", "\x00\xff", "nice:sign-in", "ˮ"} {
		got := safe(s)
		if strings.ContainsAny(got, "~+/\\*?[]: ") || got == "." || got == ".." {
			t.Errorf("safe(%q) = %q holds a separator, a glob or path character", s, got)
		}
	}
	if got := safe("a.b"); got != "a.2eb" {
		t.Errorf("safe(%q) = %q, want a.2eb", "a.b", got)
	}
	if got := safe("ˮ"); got != ".cb.ae" {
		t.Errorf("safe(ˮ) = %q, want .cb.ae (each byte of the UTF-8 form)", got)
	}
}

func TestDeleteSubjectLeavesEveryOtherSubject(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store[1]") // a glob character in the directory must not matter
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []string{"alice", "alice2", "alice.", "bob.example", "bobˮxample"}
	for _, sub := range subjects {
		_ = s.SaveRefreshToken(bg, sub, "rt-"+sub)
		_ = s.SaveToken(bg, Key{Subject: sub, Audience: "navi", Project: "prj_a"}, Token{Access: "at-" + sub})
		_ = s.SaveToken(bg, Key{Subject: sub, Audience: "navi", Project: "prj_a", Org: "org_b"}, Token{Access: "at-" + sub})
	}
	if err := s.DeleteSubject(bg, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSubject(bg, "bob.example"); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"alice", "bob.example"} {
		if _, err := s.RefreshToken(bg, sub); !errors.Is(err, ErrNotConnected) {
			t.Errorf("%q still has a refresh token: %v", sub, err)
		}
		if _, ok, _ := s.LoadToken(bg, Key{Subject: sub, Audience: "navi", Project: "prj_a"}); ok {
			t.Errorf("%q still has an access token", sub)
		}
	}
	for _, sub := range []string{"alice2", "alice.", "bobˮxample"} {
		if rt, err := s.RefreshToken(bg, sub); err != nil || rt != "rt-"+sub {
			t.Errorf("deleting another subject removed the refresh token of %q: %q %v", sub, rt, err)
		}
		for _, org := range []string{"", "org_b"} {
			if tok, ok, _ := s.LoadToken(bg, Key{Subject: sub, Audience: "navi", Project: "prj_a", Org: org}); !ok || tok.Access != "at-"+sub {
				t.Errorf("deleting another subject removed the token of %q in %q", sub, org)
			}
		}
	}
	if n := len(fileNames(t, dir)); n != 9 {
		t.Fatalf("three subjects of three files each are left, got %v", fileNames(t, dir))
	}
}

func fileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestASubjectNeverGetsTheSessionOfAnother(t *testing.T) {
	clk := newClock()
	f := newFakeNice(t, clk)
	s, _ := NewFileStore(t.TempDir())
	c := userClient(t, f, s, nil)
	victim, other := "bob.example", "bobˮxample"
	_ = s.SaveRefreshToken(bg, victim, f.session())
	if _, err := c.Token(bg, Key{Subject: victim, Audience: "navi", Project: "prj_a"}); err != nil {
		t.Fatal(err)
	}
	if c.Connected(bg, other) {
		t.Fatalf("%q is connected with the session of %q", other, victim)
	}
	if _, err := c.Token(bg, Key{Subject: other, Audience: "navi", Project: "prj_a"}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Token for %q: %v, want ErrNotConnected", other, err)
	}
	if _, err := c.SignInToken(bg, other); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("SignInToken for %q: %v, want ErrNotConnected", other, err)
	}
	if _, err := s.RefreshToken(bg, "a\xfe"); !errors.Is(err, ErrNotConnected) {
		t.Fatal("a fresh subject has no refresh token")
	}
	_ = s.SaveRefreshToken(bg, "a\xff", "rt")
	if _, err := s.RefreshToken(bg, "a\xfe"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("invalid UTF-8 subjects share a session: %v", err)
	}
}

func TestAnUpgradeKeepsSimpleSubjectsAndDropsOldFilesOfOthers(t *testing.T) {
	dir := t.TempDir()
	// Files as v0.1.0 wrote them.
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("refresh-usr_123-abc", "rt-simple")
	write("refresh-alice~40corp~2eid", "rt-email")
	s, _ := NewFileStore(dir)
	if rt, err := s.RefreshToken(bg, "usr_123-abc"); err != nil || rt != "rt-simple" {
		t.Fatalf("a simple subject keeps its session across the upgrade: %q %v", rt, err)
	}
	if _, err := s.RefreshToken(bg, "alice@corp.id"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("a file of the old form is never read for a subject with other characters: %v", err)
	}
}
