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
	Auth        bool // an auth check is visible on the line or in the file
	UserInput   bool // the handler/line references user-controlled input
	RateLimited bool // a rate-limit/throttle guard is visible near the route
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
	cs  = exts(".cs")
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
	// ASP.NET Core Minimal APIs: app.MapGet("/path", ...). Auth guard, when
	// present, chains on the same line (.RequireAuthorization()).
	{"ASP.NET Minimal", cs, regexp.MustCompile(`\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]+)"`), 1, 0},
}

// authRe matches signs that a route is authenticated.
var authRe = regexp.MustCompile(`(?i)login_required|authenticate|requireauth|isauthenticated|ensurelogged|before_action[^#\n]*(?:authenticate|require_login)|middleware\(\s*['"]auth|@auth\b|verify_?jwt|passport\.|requiresauth|\[authorize|authorization|jwt_required|permission_required`)

// rateLimitRe matches a rate-limit / throttle guard.
var rateLimitRe = regexp.MustCompile(`(?i)rate[_-]?limit|ratelimit|throttle|slowdown|express-rate|limiter|@limiter|Throttle|bucket4j|rack-attack`)

// inputRe matches user-controlled input references.
var inputRe = regexp.MustCompile(`req\.(?:query|params|body)|request\.(?:args|form|json|data|params|GET|POST)|params\[|\$_(?:GET|POST|REQUEST)|c\.(?:Query|Param|PostForm)`)

// Map returns the routes discovered under root.
func Map(root string, ignore []string) ([]Route, error) {
	files, err := scanner.WalkText(root, ignore)
	if err != nil {
		return nil, err
	}
	// ASP.NET apps commonly require auth globally (a fallback policy or an MVC
	// AuthorizeFilter) so every endpoint is authenticated unless it opts out with
	// [AllowAnonymous]. Detect that first, so controllers without a visible
	// [Authorize] aren't wrongly flagged no-auth.
	dotnetGlobalAuth := detectDotnetGlobalAuth(files)

	var out []Route
	for _, f := range files {
		ext := filepath.Ext(f.Path)
		if ext == ".rb" {
			out = append(out, railsResources(f)...)
		}
		if ext == ".graphql" || ext == ".gql" {
			out = append(out, graphqlOps(f)...)
		}
		if ext == ".cs" {
			out = append(out, dotnetRoutes(f, dotnetGlobalAuth)...)
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
					Auth:        windowMatch(f.Lines, lineNo, m.authWindow, authRe),
					UserInput:   inputRe.MatchString(line),
					RateLimited: rateLimitRe.MatchString(line), // inline middleware on the route line
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

// --- ASP.NET Core attribute routing: [Route] on the controller + [HttpX] on ---
// --- each action, with [Authorize]/[AllowAnonymous] deciding auth.          ---

var (
	reCsClass      = regexp.MustCompile(`\bclass\s+(\w+)`)
	reCsRoute      = regexp.MustCompile(`\[Route\s*\(\s*"([^"]*)"`)
	reCsHttp       = regexp.MustCompile(`\[Http(Get|Post|Put|Delete|Patch|Head|Options)\b(?:\s*\(\s*"([^"]*)")?`)
	reCsAuthorize  = regexp.MustCompile(`\[Authorize\b`)
	reCsAnon       = regexp.MustCompile(`\[AllowAnonymous\b`)
	reCsRouteConst = regexp.MustCompile(`\{(\w+)[:?][^}]*\}`) // {id:guid} / {id?} -> {id}
)

// auth tri-state for a controller/action.
const (
	authUnknown = iota
	authRequired
	authAnon
)

// dotnetRoutes maps an ASP.NET Core controller: it combines the controller's
// [Route] prefix with each action's [HttpX("...")] path, and reads
// [Authorize]/[AllowAnonymous] (action-level overriding controller-level) to
// judge auth. An action path starting with "/" is absolute and ignores the
// prefix — matching ASP.NET's own routing.
func dotnetRoutes(f scanner.TextFile, globalAuth bool) []Route {
	var out []Route
	className := ""
	classPrefix := ""
	classAuth := authUnknown
	seenClass := false

	pendingRoute := ""   // a [Route(...)] seen but not yet attached
	pendingAuth := authUnknown

	for lineNo, line := range f.Lines {
		if m := reCsRoute.FindStringSubmatch(line); m != nil {
			pendingRoute = m[1]
		}
		if reCsAuthorize.MatchString(line) {
			pendingAuth = authRequired
		}
		if reCsAnon.MatchString(line) {
			pendingAuth = authAnon
		}

		// An HTTP verb attribute marks an endpoint.
		if hm := reCsHttp.FindStringSubmatch(line); hm != nil {
			method := strings.ToUpper(hm[1])
			action := hm[2]
			if action == "" {
				action = pendingRoute // [HttpGet] paired with a separate [Route("...")]
			}
			path := dotnetPath(classPrefix, action, className)
			// Resolve auth: action-level attribute wins, else controller-level,
			// else the app-wide default (a global filter makes it required).
			auth := classAuth
			if pendingAuth != authUnknown {
				auth = pendingAuth
			}
			if auth == authUnknown && globalAuth {
				auth = authRequired
			}
			out = append(out, Route{
				Method:    method,
				Path:      path,
				Framework: "ASP.NET Core",
				File:      f.Path,
				Line:      lineNo + 1,
				Auth:      auth == authRequired,
				UserInput: method != "GET" || strings.Contains(path, "{"),
			})
			pendingRoute = ""
			pendingAuth = authUnknown
			continue
		}

		// The controller class declaration consumes the attributes above it.
		if m := reCsClass.FindStringSubmatch(line); m != nil {
			className = m[1]
			classPrefix = pendingRoute
			classAuth = pendingAuth
			seenClass = true
			pendingRoute = ""
			pendingAuth = authUnknown
		}
	}
	_ = seenClass
	return out
}

// dotnetPath composes the final route from a controller prefix and an action
// path, expanding the [controller] token and stripping route constraints.
func dotnetPath(prefix, action, controller string) string {
	action = strings.TrimSpace(action)
	var p string
	switch {
	case strings.HasPrefix(action, "/"):
		p = action // absolute — ignores the controller prefix
	default:
		pre := strings.Trim(prefix, "/")
		act := strings.Trim(action, "/")
		switch {
		case pre == "" && act == "":
			p = "/"
		case pre == "":
			p = "/" + act
		case act == "":
			p = "/" + pre
		default:
			p = "/" + pre + "/" + act
		}
	}
	ctrl := strings.ToLower(strings.TrimSuffix(controller, "Controller"))
	p = strings.ReplaceAll(p, "[controller]", ctrl)
	p = strings.ReplaceAll(p, "[action]", "")
	p = reCsRouteConst.ReplaceAllString(p, "{$1}")
	p = strings.ReplaceAll(p, "//", "/")
	if p == "" {
		p = "/"
	}
	return p
}

// reCsGlobalAuth signals an app-wide authorization requirement: an MVC
// AuthorizeFilter, a fallback/default policy, or MapControllers().RequireAuthorization().
var reCsGlobalAuth = regexp.MustCompile(`AuthorizeFilter|FallbackPolicy|DefaultPolicy|\.RequireAuthorization\s*\(`)
var reCsRequireAuthed = regexp.MustCompile(`RequireAuthenticatedUser|RequireAuthorization`)

// detectDotnetGlobalAuth reports whether the app enforces authentication
// globally, so an endpoint with no visible [Authorize] should still be treated
// as authenticated (only [AllowAnonymous] opts out).
func detectDotnetGlobalAuth(files []scanner.TextFile) bool {
	for _, f := range files {
		if filepath.Ext(f.Path) != ".cs" {
			continue
		}
		base := filepath.Base(f.Path)
		if base != "Program.cs" && base != "Startup.cs" {
			continue // the global policy is configured in app startup
		}
		var hasFilter, requiresAuthed bool
		for _, line := range f.Lines {
			if reCsGlobalAuth.MatchString(line) {
				hasFilter = true
			}
			if reCsRequireAuthed.MatchString(line) {
				requiresAuthed = true
			}
		}
		if hasFilter && requiresAuthed {
			return true
		}
	}
	return false
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
