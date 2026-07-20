package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The marker line lets us recognise a hook we installed, so uninstall is safe
// and install never clobbers someone else's pre-commit hook.
const hookMarker = "# managed by andas — https://github.com/malandas/andas"

const hookScript = `#!/bin/sh
` + hookMarker + `
# Blocks a commit that would add real security risk. Runs offline so it's fast
# and needs no network; secrets and entropy hits are caught before they land in
# history. Override a false positive with:  git commit --no-verify
if command -v andas >/dev/null 2>&1; then
  andas scan . --offline --fail-on medium || {
    echo ""
    echo "andas: commit blocked — resolve the findings above, or re-run with 'git commit --no-verify' to override."
    exit 1
  }
fi
`

// runHook implements `andas hook <install|uninstall|status>`.
func runHook(args []string) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	hookPath, err := preCommitPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}

	switch sub {
	case "install":
		return hookInstall(hookPath)
	case "uninstall":
		return hookUninstall(hookPath)
	case "status":
		return hookStatus(hookPath)
	default:
		fmt.Fprintf(os.Stderr, "andas: unknown hook command %q (use install|uninstall|status)\n", sub)
		return 2
	}
}

// preCommitPath asks git for the correct hooks path (honouring worktrees and
// core.hooksPath) and returns the pre-commit file location.
func preCommitPath() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository (run this inside your repo)")
	}
	hooksDir := strings.TrimSpace(string(out))
	return filepath.Join(hooksDir, "pre-commit"), nil
}

func hookInstall(path string) int {
	if existing, err := os.ReadFile(path); err == nil {
		if strings.Contains(string(existing), hookMarker) {
			fmt.Println("andas: pre-commit hook already installed.")
			return 0
		}
		fmt.Fprintf(os.Stderr, "andas: a different pre-commit hook already exists at %s\n", path)
		fmt.Fprintln(os.Stderr, "andas: remove or merge it manually, then re-run — refusing to overwrite it.")
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}
	if err := os.WriteFile(path, []byte(hookScript), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}
	fmt.Printf("andas: pre-commit hook installed at %s\n", path)
	fmt.Println("andas: commits are now scanned for secrets before they land. Override with 'git commit --no-verify'.")
	return 0
}

func hookUninstall(path string) int {
	existing, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("andas: no pre-commit hook to remove.")
		return 0
	}
	if !strings.Contains(string(existing), hookMarker) {
		fmt.Fprintln(os.Stderr, "andas: the pre-commit hook here wasn't installed by andas — leaving it untouched.")
		return 1
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}
	fmt.Println("andas: pre-commit hook removed.")
	return 0
}

func hookStatus(path string) int {
	existing, err := os.ReadFile(path)
	switch {
	case err != nil:
		fmt.Println("andas: not installed. Run 'andas hook install' to guard your commits.")
	case strings.Contains(string(existing), hookMarker):
		fmt.Printf("andas: installed at %s\n", path)
	default:
		fmt.Printf("andas: a non-andas pre-commit hook exists at %s\n", path)
	}
	return 0
}
