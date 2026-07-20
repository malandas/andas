// Package iac scans infrastructure-as-code and CI config — Dockerfiles,
// docker-compose, and GitHub Actions workflows — for insecure settings. Every
// repo has these files, and each carries its own class of high-impact mistakes:
// containers running as root, the Docker socket mounted into a service, secrets
// exposed to untrusted pull requests, script injection in a workflow. Rules are
// tight and high-signal, matched by file kind rather than by extension alone.
package iac

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "iac" }

type rule struct {
	id, title string
	sev       finding.Severity
	kind      string // "dockerfile" | "compose" | "gha"
	pat       *regexp.Regexp
	fix       string
}

var rules = []rule{
	// --- Dockerfile ---
	{"docker-user-root", "Container configured to run as root", finding.SevMedium, "dockerfile",
		regexp.MustCompile(`(?i)^\s*USER\s+root\b`),
		"Add a non-root USER; a root container that's breached is a root host process."},
	{"docker-latest-tag", "Base image pinned to :latest", finding.SevLow, "dockerfile",
		regexp.MustCompile(`(?i)^\s*FROM\s+\S+:latest\b`),
		"Pin the base image to a specific version or digest for reproducible, auditable builds."},
	{"docker-add-remote", "ADD used with a remote URL", finding.SevMedium, "dockerfile",
		regexp.MustCompile(`(?i)^\s*ADD\s+https?://`),
		"Use COPY for local files; for remote ones, curl + checksum-verify so the content is checked."},
	{"docker-curl-pipe-sh", "Remote script piped straight to a shell", finding.SevHigh, "dockerfile",
		regexp.MustCompile(`(?i)(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b`),
		"Download, verify a checksum/signature, then execute — piping to a shell trusts the server blindly."},
	{"docker-chmod-777", "World-writable permissions (chmod 777)", finding.SevMedium, "dockerfile",
		regexp.MustCompile(`chmod\s+(?:-R\s+)?0?777\b`),
		"Grant the minimum permissions the process actually needs."},

	// --- docker-compose ---
	{"compose-privileged", "Privileged container", finding.SevHigh, "compose",
		regexp.MustCompile(`(?i)privileged:\s*true`),
		"A privileged container can escape to the host; drop it and add only the capabilities you need."},
	{"compose-docker-sock", "Docker socket mounted into a container", finding.SevHigh, "compose",
		regexp.MustCompile(`/var/run/docker\.sock`),
		"Mounting docker.sock grants root-equivalent control of the host; avoid it or use a proxy."},
	{"compose-host-network", "Host network mode", finding.SevMedium, "compose",
		regexp.MustCompile(`(?i)network_mode:\s*["']?host`),
		"Host networking removes container isolation; use a bridge network and publish only needed ports."},

	// --- GitHub Actions ---
	{"gha-script-injection", "Untrusted input in a workflow (script-injection risk)", finding.SevHigh, "gha",
		regexp.MustCompile(`\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|discussion|head_commit|pages)\.)`),
		"Never interpolate github.event.* / head_ref into a run: script; pass it via an env var and quote it."},
	{"gha-pull-request-target", "pull_request_target runs with secrets on untrusted code", finding.SevMedium, "gha",
		regexp.MustCompile(`\bpull_request_target\b`),
		"pull_request_target has repo secrets; never check out and run untrusted PR code under it."},
	{"gha-unpinned-action", "Third-party action pinned to a moving ref", finding.SevMedium, "gha",
		regexp.MustCompile(`(?i)uses:\s*[^@\s]+@(?:main|master)\b`),
		"Pin third-party actions to a full commit SHA; a moving branch can be changed under you."},
}

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	files, err := scanner.WalkText(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, f := range files {
		kind := fileKind(f.Path)
		if kind == "" {
			continue
		}
		for lineNo, line := range f.Lines {
			for _, r := range rules {
				if r.kind != kind || !r.pat.MatchString(line) {
					continue
				}
				out = append(out, finding.Finding{
					Kind:     finding.KindConfig,
					RuleID:   r.id,
					Title:    r.title,
					File:     f.Path,
					Line:     lineNo + 1,
					Match:    snippet(line),
					Severity: r.sev,
					Fix:      r.fix,
					Context:  finding.Context{Note: kindLabel(kind) + " misconfiguration"},
				})
			}
		}
	}
	return out, nil
}

// fileKind classifies a path into the config family whose rules apply, or "".
func fileKind(path string) string {
	base := filepath.Base(path)
	dir := filepath.ToSlash(filepath.Dir(path))
	switch {
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile"):
		return "dockerfile"
	case base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml":
		return "compose"
	case strings.Contains(dir, ".github/workflows") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return "gha"
	}
	return ""
}

func kindLabel(kind string) string {
	switch kind {
	case "dockerfile":
		return "Dockerfile"
	case "compose":
		return "docker-compose"
	case "gha":
		return "GitHub Actions"
	}
	return kind
}

func snippet(line string) string {
	s := strings.TrimSpace(line)
	if len(s) > 100 {
		s = s[:99] + "…"
	}
	return s
}
