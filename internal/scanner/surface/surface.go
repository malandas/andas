// Package surface maps a web application's attack surface from its source: the
// routes/endpoints it exposes, which HTTP method each takes, and whether an
// authentication check is visible nearby. It is built for AUTHORISED security
// assessment — a pentester or bug-bounty researcher handed a codebase who needs
// a fast, prioritised map of where to start. It only reads source; it never
// touches a live target.
package surface

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/malandas/andas/internal/scanner"
)

// Route is one discovered endpoint.
type Route struct {
	Method    string
	Path      string
	Framework string
	File      string
	Line      int
	Auth      bool // an auth check is visible on the line or in the file
	UserInput bool // the handler/line references user-controlled input
}

type matcher struct {
	framework  string
	exts       map[string]bool
	re         *regexp.Regexp // group 1 = method (or ""), group 2 = path
	methodIn   int            // index of the method group, 0 if implicit GET
	authWindow int            // lines around the route to check for an auth guard
}

func exts(e ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range e {
		m[x] = true
	}
	return m
}

var (
	web = exts(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
	py  = exts(".py")
	rb  = exts(".rb")
	php = exts(".php")
	go_ = exts(".go")
)

var matchers = []matcher{
	// Inline-middleware frameworks: the auth guard is on the route line itself.
	{"Express", web, regexp.MustCompile(`(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)`), 1, 0},
	{"Gin/Go", go_, regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH|Any|Handle)\s*\(\s*"([^"]+)"`), 1, 0},
	{"Laravel", php, regexp.MustCompile(`Route::(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)`), 1, 0},
	{"Rails", rb, regexp.MustCompile(`^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)`), 1, 0},
	{"Django", py, regexp.MustCompile(`(?:path|re_path|url)\s*\(\s*r?['"]([^'"]*)`), 0, 0},
	// Decorator frameworks: the auth guard is an adjacent decorator line.
	{"Flask/FastAPI", py, regexp.MustCompile(`@(?:app|bp|router|blueprint)\.(route|get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)`), 1, 2},
}

// authRe matches signs that a route is authenticated.
var authRe = regexp.MustCompile(`(?i)login_required|authenticate|requireauth|isauthenticated|ensurelogged|before_action[^#\n]*(?:authenticate|require_login)|middleware\(\s*['"]auth|@auth\b|verify_?jwt|passport\.|requiresauth|\[authorize|authorization|jwt_required|permission_required`)

// inputRe matches user-controlled input references.
var inputRe = regexp.MustCompile(`req\.(?:query|params|body)|request\.(?:args|form|json|data|params|GET|POST)|params\[|\$_(?:GET|POST|REQUEST)|c\.(?:Query|Param|PostForm)`)

// Map returns the routes discovered under root.
func Map(root string, ignore []string) ([]Route, error) {
	files, err := scanner.WalkText(root, ignore)
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, f := range files {
		ext := filepath.Ext(f.Path)
		for _, m := range matchers {
			if !m.exts[ext] {
				continue
			}
			for lineNo, line := range f.Lines {
				sm := m.re.FindStringSubmatch(line)
				if sm == nil {
					continue
				}
				method, path := "GET", ""
				if m.methodIn == 1 {
					method = normMethod(sm[1])
					path = sm[2]
				} else {
					path = sm[1]
				}
				if path == "" {
					continue
				}
				out = append(out, Route{
					Method:    method,
					Path:      path,
					Framework: m.framework,
					File:      f.Path,
					Line:      lineNo + 1,
					// Auth is judged from a per-framework window: 0 lines (the
					// route line itself) for inline-middleware frameworks, a couple
					// for decorator ones — so an unrelated `require('auth')` or a
					// neighbouring route's guard doesn't count.
					Auth:      windowMatch(f.Lines, lineNo, m.authWindow, authRe),
					UserInput: inputRe.MatchString(line),
				})
			}
		}
	}
	return out, nil
}

// windowMatch reports whether re matches within `w` lines of lineNo.
func windowMatch(lines []string, lineNo, w int, re *regexp.Regexp) bool {
	lo, hi := lineNo-w, lineNo+w
	if lo < 0 {
		lo = 0
	}
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	for i := lo; i <= hi; i++ {
		if re.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func normMethod(s string) string {
	s = strings.ToUpper(s)
	if s == "ROUTE" || s == "HANDLE" || s == "ALL" || s == "ANY" {
		return "ANY"
	}
	return s
}
