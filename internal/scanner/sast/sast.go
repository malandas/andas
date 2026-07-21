package sast

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "sast" }

// taintRe matches the common user-controlled input sources across languages. A
// dangerous sink on the same line as one of these is much likelier to be a real,
// reachable vulnerability than one fed by a constant.
var taintRe = regexp.MustCompile(
	`req\.(?:query|params|body|headers)\b|request\.(?:args|form|values|data|GET|POST|params)\b|\bparams\[|\$_(?:GET|POST|REQUEST|COOKIE)\b|r\.(?:FormValue|URL\.Query|PostFormValue)\b|process\.argv|sys\.argv|\binput\s*\(`)

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	files, err := scanner.WalkText(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, f := range files {
		ext := filepath.Ext(f.Path)
		// Pre-compute, per line, whether user-controlled input reaches it — either
		// directly on the line or via a variable assigned from a source earlier in
		// the same function (a light intra-procedural taint flow).
		tainted := taintedLines(f.Lines, ext)
		for lineNo, line := range f.Lines {
			// Skip minified/generated lines and comment lines — a pattern match
			// there is almost always noise, not a real sink.
			if len(line) > 1000 || isComment(line, ext) {
				continue
			}
			for _, r := range rules {
				if !r.exts[ext] || !r.pat.MatchString(line) {
					continue
				}
				userInput := tainted[lineNo]
				note := r.cwe + " — pattern-based detection"
				if userInput {
					note = r.cwe + " — user-controlled input reaches this line; likely exploitable"
				}
				out = append(out, finding.Finding{
					Kind:     finding.KindCode,
					RuleID:   r.id,
					Title:    r.title,
					File:     f.Path,
					Line:     lineNo + 1,
					Match:    snippet(line),
					Severity: r.sev,
					Fix:      r.fix,
					Context:  finding.Context{CWE: r.cwe, UserInput: userInput, Note: note},
				})
			}
		}
	}
	return out, nil
}

// isComment reports whether a line is (starts as) a comment, so a pattern that
// appears in commented-out code or documentation doesn't fire. It handles only
// the leading-marker case — good enough to kill the common false positives.
func isComment(line, ext string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	switch ext {
	case ".py", ".rb":
		return strings.HasPrefix(t, "#")
	case ".php":
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") ||
			strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
	default: // js/ts/go/rust and the rest use C-style comments
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
	}
}

// snippet trims a source line to a short, safe-to-print excerpt.
func snippet(line string) string {
	const max = 100
	s := line
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}
