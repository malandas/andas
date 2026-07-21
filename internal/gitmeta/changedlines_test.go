package gitmeta

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIntroduced(t *testing.T) {
	changed := map[string]map[int]bool{
		"/repo/a.go": {5: true, 6: true},
		"/repo/new.go": {0: true}, // wholly new file
	}
	if !Introduced(changed, "/repo/a.go", 5) {
		t.Error("line 5 was changed → introduced")
	}
	if Introduced(changed, "/repo/a.go", 9) {
		t.Error("line 9 was not changed → not introduced")
	}
	if !Introduced(changed, "/repo/new.go", 999) {
		t.Error("any line of a wholly-new file is introduced")
	}
	if Introduced(changed, "/repo/untouched.go", 1) {
		t.Error("an untouched file is never introduced")
	}
}

func TestChangedLines_Integration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t.co", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t.co")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	run("init")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("l1\nl2\nl3\n"), 0o644)
	run("add", "-A")
	run("commit", "-m", "base")
	// Modify line 2, add a brand-new file.
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("l1\nCHANGED\nl3\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "new.txt"), []byte("x\ny\n"), 0o644)

	cl, err := ChangedLines(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	aAbs, _ := filepath.Abs(filepath.Join(dir, "a.txt"))
	if !cl[aAbs][2] {
		t.Errorf("line 2 of a.txt should be marked changed; got %v", cl[aAbs])
	}
	if cl[aAbs][1] || cl[aAbs][3] {
		t.Errorf("unchanged lines 1/3 must not be marked; got %v", cl[aAbs])
	}
	newAbs, _ := filepath.Abs(filepath.Join(dir, "new.txt"))
	if !cl[newAbs][0] {
		t.Errorf("wholly-new file should map to {0:true}; got %v", cl[newAbs])
	}
}
