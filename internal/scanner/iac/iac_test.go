package iac

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
)

func scan(t *testing.T, rel, src string) []finding.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(src), 0o644)
	f, err := New().Scan(dir, scanner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func hasRule(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestFileKind(t *testing.T) {
	cases := map[string]string{
		"Dockerfile": "dockerfile", "api.Dockerfile": "dockerfile",
		"docker-compose.yml": "compose", "compose.yaml": "compose",
		".github/workflows/ci.yml": "gha", "README.md": "", "app.js": "",
	}
	for path, want := range cases {
		if got := fileKind(path); got != want {
			t.Errorf("fileKind(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIaC_Dockerfile(t *testing.T) {
	src := "FROM node:latest\nUSER root\nADD https://x/i.sh /tmp/\nRUN curl -fsSL https://x | bash\n"
	fs := scan(t, "Dockerfile", src)
	for _, id := range []string{"docker-latest-tag", "docker-user-root", "docker-add-remote", "docker-curl-pipe-sh"} {
		if !hasRule(fs, id) {
			t.Errorf("Dockerfile: missing rule %q", id)
		}
	}
}

func TestIaC_Compose(t *testing.T) {
	src := "services:\n  x:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
	fs := scan(t, "docker-compose.yml", src)
	if !hasRule(fs, "compose-privileged") || !hasRule(fs, "compose-docker-sock") {
		t.Errorf("compose rules missing: %v", fs)
	}
}

func TestIaC_GitHubActions(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  b:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n      - uses: some/action@main\n"
	fs := scan(t, ".github/workflows/ci.yml", src)
	for _, id := range []string{"gha-pull-request-target", "gha-script-injection", "gha-unpinned-action"} {
		if !hasRule(fs, id) {
			t.Errorf("GHA: missing rule %q", id)
		}
	}
}

func TestIaC_IgnoresNonConfigFiles(t *testing.T) {
	// The same content in a plain file must not trigger config rules.
	if fs := scan(t, "notes.txt", "privileged: true\nUSER root\n"); len(fs) != 0 {
		t.Errorf("non-config file should be clean, got %v", fs)
	}
}
