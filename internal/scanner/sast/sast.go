package sast

import (
	"fmt"
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
	`req\.(?:query|params|body|headers)\b|request\.(?:args|form|values|data|GET|POST|params)\b|\bparams\[|\$_(?:GET|POST|REQUEST|COOKIE)\b|r\.(?:FormValue|URL\.Query|PostFormValue)\b|process\.argv|sys\.argv|\binput\s*\(|Request\.(?:Query|Form|Headers|Cookies|Body|QueryString|RouteValues|Params)\b|\[From(?:Query|Route|Form|Body|Header)\]`)

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	files, err := scanner.WalkText(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}
	// Built-in rules plus any user-defined rules from .andas-rules.yml.
	active := rules
	if custom := loadCustomRules(root); len(custom) > 0 {
		active = append(append([]rule{}, rules...), custom...)
	}

	// [IgnoreAntiforgeryToken] is only a real CSRF risk when the app validates
	// antiforgery globally (there's then something to opt out of). Detect that
	// once, up front, so the rule stays silent on apps that don't — avoiding a
	// wave of findings on a harmless, no-op attribute.
	globalAntiforgery := dotnetGlobalAntiforgery(files)

	// Pre-compute, per file and line, whether user-controlled input reaches it —
	// following taint within a function, across a call chain, and across file
	// boundaries (controller → service). A tainted sink is far likelier real.
	taintByFile := crossFileTaint(files)

	var out []finding.Finding
	for _, f := range files {
		ext := filepath.Ext(f.Path)
		ft := taintByFile[f.Path]
		tainted := ft.tainted
		for lineNo, line := range f.Lines {
			// Skip minified/generated lines and comment lines — a pattern match
			// there is almost always noise, not a real sink.
			if len(line) > 1000 || isComment(line, ext) {
				continue
			}
			for _, r := range active {
				if !r.exts[ext] || !r.pat.MatchString(line) {
					continue
				}
				// Context gate: skip the CSRF opt-out finding unless global
				// antiforgery makes the attribute actually disable something.
				if r.id == "cs-csrf-disabled" && !globalAntiforgery {
					continue
				}
				userInput := tainted[lineNo]
				// An XSS sink fed HTML-encoded input isn't actually exploitable —
				// don't raise its confidence. (Only affects CWE-79; other injection
				// classes are unaffected by HTML encoding.)
				if userInput && r.cwe == "CWE-79" && lineNo < len(ft.htmlSafe) && ft.htmlSafe[lineNo] {
					userInput = false
				}
				note := r.cwe + " — pattern-based detection"
				if userInput {
					note = r.cwe + " — user-controlled input reaches this line; likely exploitable"
					// Show where the input entered, when it's a different line — the
					// flow a reviewer follows from source to sink.
					if o := ft.origin; lineNo < len(o) && o[lineNo] != 0 && o[lineNo] != lineNo+1 {
						note += fmt.Sprintf(" (input enters at line %d)", o[lineNo])
					}
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
			// IDOR needs a window (no ownership check nearby), so it's checked
			// separately from the pure-regex rules.
			if idorExts[ext] && detectIDOR(f.Lines, lineNo) {
				out = append(out, finding.Finding{
					Kind:     finding.KindCode,
					RuleID:   "idor",
					Title:    "Possible IDOR — object fetched by user id with no ownership check",
					File:     f.Path,
					Line:     lineNo + 1,
					Match:    snippet(line),
					Severity: finding.SevHigh,
					Fix:      "Scope the query to the current user, or verify ownership/authorization before returning the object.",
					Context:  finding.Context{CWE: "CWE-639", UserInput: true, Note: "CWE-639 — user-controlled object id with no nearby ownership check"},
				})
			}
		}
	}
	return out, nil
}

var idorExts = merge(js, py, ruby, php)

// reCsAutoAntiforgery marks app-wide antiforgery validation: the global
// AutoValidateAntiforgeryToken filter/attribute (as a Filters.Add(...) in
// startup or an attribute on a base controller).
var reCsAutoAntiforgery = regexp.MustCompile(`AutoValidateAntiforgeryToken`)

// dotnetGlobalAntiforgery reports whether the app validates antiforgery tokens
// globally, so that an [IgnoreAntiforgeryToken] on an action is a real opt-out
// of active protection rather than a no-op.
func dotnetGlobalAntiforgery(files []scanner.TextFile) bool {
	for _, f := range files {
		if filepath.Ext(f.Path) != ".cs" {
			continue
		}
		for _, line := range f.Lines {
			if reCsAutoAntiforgery.MatchString(line) {
				return true
			}
		}
	}
	return false
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
