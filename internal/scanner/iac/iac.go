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

	// --- Terraform ---
	{"tf-public-ingress", "Security group open to the world (0.0.0.0/0)", finding.SevHigh, "terraform",
		regexp.MustCompile(`cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"`),
		"Restrict the CIDR to known ranges; 0.0.0.0/0 exposes the port to the whole internet."},
	{"tf-public-acl", "Storage bucket ACL set to public", finding.SevHigh, "terraform",
		regexp.MustCompile(`(?i)acl\s*=\s*"public-read(?:-write)?"`),
		"Make the bucket private and grant access with scoped policies, not a public ACL."},
	{"tf-unencrypted", "Encryption explicitly disabled", finding.SevMedium, "terraform",
		regexp.MustCompile(`(?i)(?:encrypted|encryption)\s*=\s*false`),
		"Enable encryption at rest for this resource."},
	{"tf-hardcoded-secret", "Hardcoded credential in Terraform", finding.SevHigh, "terraform",
		regexp.MustCompile(`(?i)(?:password|secret_key|access_key|private_key)\s*=\s*"[^"$][^"]{6,}"`),
		"Move the secret to a variable or a secrets manager; never commit it in .tf."},
	{"tf-iam-wildcard-action", "IAM policy grants all actions (Action: *)", finding.SevHigh, "terraform",
		regexp.MustCompile(`(?i)"?(?:Action|actions)"?\s*[:=]\s*\[?\s*"\*"`),
		"Grant least privilege; never allow Action \"*\" — it is effectively admin."},
	{"tf-iam-passrole", "IAM PassRole allowed (privilege-escalation primitive)", finding.SevHigh, "terraform",
		regexp.MustCompile(`(?i)"?iam:PassRole"?`),
		"iam:PassRole lets a principal hand a more-privileged role to a service — scope it to specific roles."},
	{"tf-iam-assume-wildcard", "AssumeRole trust open to any principal (Principal: *)", finding.SevHigh, "terraform",
		regexp.MustCompile(`(?i)"?Principal"?\s*[:=]\s*(?:"\*"|\{[^}]*"AWS"\s*[:=]\s*"\*")`),
		"Restrict the trust policy to specific accounts/roles; a wildcard principal lets anyone assume it."},
	{"tf-public-rds", "Database publicly accessible", finding.SevHigh, "terraform",
		regexp.MustCompile(`(?i)publicly_accessible\s*=\s*true`),
		"Keep databases in private subnets; never expose them to the internet."},

	// --- Kubernetes ---
	{"k8s-privileged", "Privileged container", finding.SevHigh, "k8s",
		regexp.MustCompile(`(?i)privileged:\s*true`),
		"Drop privileged: true; grant only the specific capabilities the container needs."},
	{"k8s-run-as-root", "Container allowed to run as root", finding.SevMedium, "k8s",
		regexp.MustCompile(`(?i)runAsNonRoot:\s*false`),
		"Set runAsNonRoot: true and a non-zero runAsUser."},
	{"k8s-host-namespace", "Pod shares a host namespace", finding.SevHigh, "k8s",
		regexp.MustCompile(`(?i)host(?:Network|PID|IPC):\s*true`),
		"Host namespaces break pod isolation; remove them unless strictly required."},
	{"k8s-allow-priv-esc", "Privilege escalation allowed", finding.SevMedium, "k8s",
		regexp.MustCompile(`(?i)allowPrivilegeEscalation:\s*true`),
		"Set allowPrivilegeEscalation: false in the container securityContext."},
}

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	files, err := scanner.WalkText(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, f := range files {
		kind := classify(f.Path, f.Lines)
		if kind == "" {
			continue
		}
		for lineNo, line := range f.Lines {
			for _, r := range rules {
				if r.kind != kind || !r.pat.MatchString(line) {
					continue
				}
				// Passing untrusted input via an env/output/with VALUE is the
				// recommended mitigation — don't flag the safe pattern, only its
				// use embedded in a run: script.
				if r.id == "gha-script-injection" && ghaSafeExprAssignment(line) {
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

// classify decides which config family's rules apply to a file. Dockerfiles,
// compose files, workflows, and Terraform are recognised by name; Kubernetes
// manifests are recognised by content (a YAML with apiVersion + kind), since
// they have no distinguishing filename.
func classify(path string, lines []string) string {
	base := filepath.Base(path)
	dir := filepath.ToSlash(filepath.Dir(path))
	isYAML := strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
	switch {
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile"):
		return "dockerfile"
	case base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml":
		return "compose"
	case strings.Contains(dir, ".github/workflows") && isYAML:
		return "gha"
	case strings.HasSuffix(base, ".tf"):
		return "terraform"
	case isYAML && looksKubernetes(lines):
		return "k8s"
	}
	return ""
}

// looksKubernetes reports whether a YAML file is a Kubernetes manifest.
func looksKubernetes(lines []string) bool {
	var hasAPI, hasKind bool
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "apiVersion:") {
			hasAPI = true
		}
		if strings.HasPrefix(t, "kind:") {
			hasKind = true
		}
		if hasAPI && hasKind {
			return true
		}
	}
	return false
}

func kindLabel(kind string) string {
	switch kind {
	case "dockerfile":
		return "Dockerfile"
	case "compose":
		return "docker-compose"
	case "gha":
		return "GitHub Actions"
	case "terraform":
		return "Terraform"
	case "k8s":
		return "Kubernetes"
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

// reGhaSafeExpr matches a YAML mapping value that is ONLY a ${{ … }} expression
// — the env/output/with pattern that safely quotes untrusted input.
var reGhaSafeExpr = regexp.MustCompile(`^\s*([\w-]+):\s*"?\$\{\{[^}]*\}\}"?\s*$`)

func ghaSafeExprAssignment(line string) bool {
	m := reGhaSafeExpr.FindStringSubmatch(line)
	return m != nil && strings.ToLower(m[1]) != "run"
}
