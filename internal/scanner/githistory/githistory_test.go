package githistory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/malandas/andas/internal/scanner"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir,
		"-c", "user.email=test@andas.dev", "-c", "user.name=andas test"}, args...)
	if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// A secret committed then removed must still surface from history — this is the
// whole point of the scanner, exercised end-to-end against a real repo.
func TestScan_FindsRemovedSecretInHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	// Build the token from split literals so this test's own source stays clean.
	secret := "sk_live_" + "51H8xLmNoPqRsTuVwXyZ1234abcd"
	file := filepath.Join(dir, "config.js")

	git(t, dir, "init")
	if err := os.WriteFile(file, []byte("const k = \""+secret+"\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-m", "add config with secret")

	// Remove the secret from HEAD — but it lives on in history.
	if err := os.WriteFile(file, []byte("const k = process.env.K;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-m", "move to env var")

	found, err := New().Scan(dir, scanner.Options{Validate: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 history finding, got %d: %+v", len(found), found)
	}
	f := found[0]
	if !strings.Contains(f.Title, "git history") {
		t.Errorf("title should mark a history finding, got %q", f.Title)
	}
	if strings.Contains(f.Match, secret) {
		t.Error("the raw secret leaked into the finding — it must be redacted")
	}
	if f.RuleID != "stripe-secret" {
		t.Errorf("rule = %q, want stripe-secret", f.RuleID)
	}
}

// A secret that is STILL in the working tree is the file scanner's job, not
// history's — the history scanner must not double-report it.
func TestScan_SkipsSecretsStillInTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	secret := "sk_live_" + "51H8xLmNoPqRsTuVwXyZ1234abcd"
	file := filepath.Join(dir, "config.js")

	git(t, dir, "init")
	os.WriteFile(file, []byte("const k = \""+secret+"\";\n"), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-m", "add config")

	found, err := New().Scan(dir, scanner.Options{Validate: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("history should skip secrets still in the tree, got %d", len(found))
	}
}
