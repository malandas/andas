package gitmeta

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.email=t@t.dev", "-c", "user.name=t"}, args...)
	if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestChangedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	git(t, dir, "init")
	os.WriteFile(filepath.Join(dir, "old.txt"), []byte("a"), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-m", "base")

	// One new untracked file after the commit.
	os.WriteFile(filepath.Join(dir, "new.txt"), []byte("b"), 0o644)

	changed, err := ChangedFiles(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	newAbs, _ := filepath.Abs(filepath.Join(dir, "new.txt"))
	oldAbs, _ := filepath.Abs(filepath.Join(dir, "old.txt"))
	if !changed[newAbs] {
		t.Error("the new untracked file should be in the changed set")
	}
	if changed[oldAbs] {
		t.Error("an unchanged committed file must not be in the set")
	}
}
