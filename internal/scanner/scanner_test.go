package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchesIgnore(t *testing.T) {
	patterns := []string{"testdata", "*.min.js", "src/generated"}
	cases := []struct {
		rel, base string
		want      bool
	}{
		{"testdata/fixture.js", "fixture.js", true},             // literal segment
		{"testdata", "testdata", true},                          // the dir itself
		{"src/generated/api.ts", "api.ts", true},                // nested path segment
		{"vendor/bundle.min.js", "bundle.min.js", true},         // glob on base
		{"src/app.js", "app.js", false},                         // unmatched
		{"my-testdata-notes.js", "my-testdata-notes.js", false}, // not a segment
	}
	for _, c := range cases {
		if got := matchesIgnore(c.rel, c.base, patterns); got != c.want {
			t.Errorf("matchesIgnore(%q,%q) = %v, want %v", c.rel, c.base, got, c.want)
		}
	}
}

func TestLoadIgnore(t *testing.T) {
	dir := t.TempDir()
	content := "# comment\n\nnode_modules\n  dist/  \n*.snap\n"
	if err := os.WriteFile(filepath.Join(dir, ".andasignore"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LoadIgnore(dir)
	want := []string{"node_modules", "dist", "*.snap"}
	if len(got) != len(want) {
		t.Fatalf("LoadIgnore = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pattern %d = %q, want %q", i, got[i], want[i])
		}
	}
	// A missing file must be silent, not an error.
	if p := LoadIgnore(t.TempDir()); p != nil {
		t.Errorf("LoadIgnore on missing file = %v, want nil", p)
	}
}

func TestWalkText_RespectsIgnore(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "keep"), 0o755)
	os.MkdirAll(filepath.Join(dir, "skip"), 0o755)
	os.WriteFile(filepath.Join(dir, "keep", "a.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "skip", "b.js"), []byte("x"), 0o644)

	files, err := WalkText(dir, []string{"skip"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if filepath.Base(filepath.Dir(f.Path)) == "skip" {
			t.Errorf("WalkText returned an ignored file: %s", f.Path)
		}
	}
	if len(files) != 1 {
		t.Errorf("WalkText returned %d files, want 1", len(files))
	}
}
