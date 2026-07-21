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
	// Go: Gin/Echo/Chi/Fiber (.GET/.Get) and net/http mux (HandleFunc).
	{"Go", go_, regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH|Any|Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]+)"`), 1, 0},
	{"Go net/http", go_, regexp.MustCompile(`(?:http\.)?(?:Handle|HandleFunc)\s*\(\s*"([^"]+)"`), 0, 0},
	{"Laravel", php, regexp.MustCompile(`Route::(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)`), 1, 0},
	{"Rails/Sinatra", rb, regexp.MustCompile(`^\s*(get|post|put|patch|delete|match)\s+['"]([^'"]+)`), 1, 0},
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
		if ext == ".rb" {
			out = append(out, railsResources(f)...)
		}
		if ext == ".graphql" || ext == ".gql" {
			out = append(out, graphqlOps(f)...)
		}
		if (ext == ".yaml" || ext == ".yml" || ext == ".json") && looksOpenAPI(f.Lines) {
			out = append(out, openapiPaths(f)...)
			continue
		}
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

// reResources matches Rails `resources :posts` / `resource :profile`.
var reResources = regexp.MustCompile(`^\s*resources?\s+:(\w+)`)

// railsResources expands a Rails `resources :x` declaration into the RESTful
// routes it generates — the endpoints a tester actually hits.
func railsResources(f scanner.TextFile) []Route {
	var out []Route
	for lineNo, line := range f.Lines {
		m := reResources.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		// Rails auth lives in the controller (before_action), not routes.rb, so
		// we can't judge it here. Default to no-auth — for a tester, a false
		// "no-auth" wastes a check, but a false "auth" hides a real endpoint.
		for _, r := range []struct{ method, path string }{
			{"GET", "/" + name}, {"POST", "/" + name},
			{"GET", "/" + name + "/:id"}, {"PUT", "/" + name + "/:id"}, {"DELETE", "/" + name + "/:id"},
		} {
			out = append(out, Route{Method: r.method, Path: r.path, Framework: "Rails (resources)",
				File: f.Path, Line: lineNo + 1, Auth: false})
		}
	}
	return out
}

// --- GraphQL: fields under `type Query`/`type Mutation` are operations ---

var reGqlType = regexp.MustCompile(`^\s*type\s+(Query|Mutation)\b`)
var reGqlField = regexp.MustCompile(`^\s*(\w+)\s*(?:\([^)]*\))?\s*:`)

func graphqlOps(f scanner.TextFile) []Route {
	var out []Route
	inOp := ""
	depth := 0
	for lineNo, line := range f.Lines {
		if m := reGqlType.FindStringSubmatch(line); m != nil {
			inOp = strings.ToUpper(m[1])
			depth = 0
			continue
		}
		if inOp == "" {
			continue
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if strings.Contains(line, "}") && depth <= 0 {
			inOp = ""
			continue
		}
		if m := reGqlField.FindStringSubmatch(line); m != nil && m[1] != "type" {
			out = append(out, Route{Method: inOp, Path: "/graphql#" + m[1], Framework: "GraphQL",
				File: f.Path, Line: lineNo + 1, UserInput: true})
		}
	}
	return out
}

// --- OpenAPI / Swagger: methods under each path in `paths:` ---

func looksOpenAPI(lines []string) bool {
	for i, l := range lines {
		if i > 30 {
			break
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "openapi:") || strings.HasPrefix(t, "swagger:") || strings.Contains(t, `"openapi"`) || strings.Contains(t, `"swagger"`) {
			return true
		}
	}
	return false
}

var reOAPath = regexp.MustCompile(`^\s{2,}(/[^\s:"]*)\s*:`)
var reOAMethod = regexp.MustCompile(`^\s{4,}(get|post|put|patch|delete)\s*:`)

func openapiPaths(f scanner.TextFile) []Route {
	var out []Route
	curPath := ""
	for lineNo, line := range f.Lines {
		if m := reOAPath.FindStringSubmatch(line); m != nil {
			curPath = m[1]
			continue
		}
		if m := reOAMethod.FindStringSubmatch(line); m != nil && curPath != "" {
			out = append(out, Route{Method: strings.ToUpper(m[1]), Path: curPath, Framework: "OpenAPI",
				File: f.Path, Line: lineNo + 1})
		}
	}
	return out
}

// HandlerSpan returns [start, end) line numbers for a route's handler: from the
// route line up to the next route in the same file (capped). Used to attribute
// dangerous sinks to the endpoint that reaches them.
func HandlerSpan(routes []Route, i int) (file string, start, end int) {
	r := routes[i]
	end = r.Line + 120 // cap: a handler this long is unusual
	for j := range routes {
		if routes[j].File == r.File && routes[j].Line > r.Line && routes[j].Line < end {
			end = routes[j].Line
		}
	}
	return r.File, r.Line, end
}
