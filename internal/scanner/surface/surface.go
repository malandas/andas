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
	// Guard describes the authorization requirement when known: "" (none),
	// "auth" (authenticated, no specific role), "role:Admin,Manager", or
	// "policy:Name". Populated for ASP.NET Core; other frameworks leave it "".
	Guard string
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
	// Controllers often inherit [Authorize] from a shared base class in another
	// file; build the class→(auth, base) map once so route auth can be resolved
	// up the inheritance chain rather than mislabelled no-auth.
	dotnetClasses := collectDotnetClasses(files)

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
			out = append(out, dotnetRoutes(f, dotnetGlobalAuth, dotnetClasses)...)
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
	reCsMethodLike = regexp.MustCompile(`^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)\b[^;={]*\(`)
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
func dotnetRoutes(f scanner.TextFile, globalAuth bool, classes map[string]dotnetClass) []Route {
	var out []Route
	className := ""
	classPrefix := ""
	classAuth := authUnknown
	classGuard := ""
	seenClass := false

	pendingRoute := ""   // a [Route(...)] seen but not yet attached
	pendingAuth := authUnknown
	pendingGuard := ""

	for lineNo, line := range f.Lines {
		if m := reCsRoute.FindStringSubmatch(line); m != nil {
			pendingRoute = m[1]
		}
		if reCsAuthorize.MatchString(line) {
			pendingAuth = authRequired
			pendingGuard = parseAuthorizeGuard(line)
		}
		if reCsAnon.MatchString(line) {
			pendingAuth = authAnon
			pendingGuard = ""
		}

		// An HTTP verb attribute marks an endpoint.
		if hm := reCsHttp.FindStringSubmatch(line); hm != nil {
			method := strings.ToUpper(hm[1])
			action := hm[2]
			if action == "" {
				action = pendingRoute // [HttpGet] paired with a separate [Route("...")]
			}
			path := dotnetPath(classPrefix, action, className)
			// Resolve auth in precedence order: action-level attribute, then
			// controller-level, then inherited from a base controller's
			// [Authorize]/[AllowAnonymous], then the app-wide default.
			auth := classAuth
			guard := classGuard
			if pendingAuth != authUnknown {
				auth = pendingAuth
				guard = pendingGuard // action-level attribute overrides the controller's
			}
			if auth == authUnknown {
				if auth = resolveInheritedAuth(className, classes); auth == authRequired {
					guard = "auth" // inherited from a base controller; role unknown here
				}
			}
			if auth == authUnknown && globalAuth {
				auth = authRequired
				guard = "auth"
			}
			if auth != authRequired {
				guard = ""
			}
			out = append(out, Route{
				Method:    method,
				Path:      path,
				Framework: "ASP.NET Core",
				File:      f.Path,
				Line:      lineNo + 1,
				Auth:      auth == authRequired,
				UserInput: method != "GET" || strings.Contains(path, "{"),
				Guard:     guard,
			})
			pendingRoute = ""
			pendingAuth = authUnknown
			pendingGuard = ""
			continue
		}

		// The controller class declaration consumes the attributes above it.
		if m := reCsClass.FindStringSubmatch(line); m != nil {
			className = m[1]
			classPrefix = pendingRoute
			classAuth = pendingAuth
			classGuard = ""
			if pendingAuth == authRequired {
				classGuard = pendingGuard
			}
			seenClass = true
			pendingRoute = ""
			pendingAuth = authUnknown
			pendingGuard = ""
		}
	}
	_ = seenClass
	return out
}

// reCsAuthorizeArgs pulls the Roles="..." / Policy="..." out of an [Authorize(...)]
// attribute so the specific guard, not just "authenticated", is recorded.
var reCsAuthorizeArgs = regexp.MustCompile(`\[Authorize\s*\(([^)]*)\)`)
var reCsRoles = regexp.MustCompile(`Roles\s*=\s*"([^"]*)"`)
var reCsPolicy = regexp.MustCompile(`Policy\s*=\s*"([^"]*)"`)

// parseAuthorizeGuard turns an [Authorize...] line into a compact guard string:
// "role:Admin,Manager", "policy:Name", or "auth" for a bare [Authorize].
func parseAuthorizeGuard(line string) string {
	m := reCsAuthorizeArgs.FindStringSubmatch(line)
	if m == nil {
		return "auth" // [Authorize] with no arguments
	}
	args := m[1]
	if r := reCsRoles.FindStringSubmatch(args); r != nil && r[1] != "" {
		return "role:" + r[1]
	}
	if p := reCsPolicy.FindStringSubmatch(args); p != nil && p[1] != "" {
		return "policy:" + p[1]
	}
	return "auth"
}

// dotnetClass records what a controller class declares for auth resolution: its
// own class-level [Authorize]/[AllowAnonymous] verdict and the base class it
// derives from (so an inherited [Authorize] can be followed up the chain).
type dotnetClass struct {
	auth int
	base string
}

// collectDotnetClasses builds a class→(auth, base) map across all .cs files so
// route auth can be resolved through inheritance, not just the attributes
// visible in the controller's own file.
func collectDotnetClasses(files []scanner.TextFile) map[string]dotnetClass {
	out := map[string]dotnetClass{}
	for _, f := range files {
		if filepath.Ext(f.Path) != ".cs" {
			continue
		}
		pendingAuth := authUnknown
		for i, line := range f.Lines {
			if reCsAuthorize.MatchString(line) {
				pendingAuth = authRequired
			}
			if reCsAnon.MatchString(line) {
				pendingAuth = authAnon
			}
			if m := reCsClass.FindStringSubmatch(line); m != nil {
				out[m[1]] = dotnetClass{auth: pendingAuth, base: dotnetBaseClass(f.Lines, i)}
				pendingAuth = authUnknown
			} else if reCsMethodLike.MatchString(line) {
				pendingAuth = authUnknown // method attributes must not leak to a later class
			}
		}
	}
	return out
}

// resolveInheritedAuth walks a controller's base-class chain, returning the
// first explicit [Authorize]/[AllowAnonymous] verdict it finds. Depth-bounded so
// a malformed or cyclic hierarchy can't loop.
func resolveInheritedAuth(className string, classes map[string]dotnetClass) int {
	c, ok := classes[className]
	if !ok {
		return authUnknown
	}
	base := c.base
	for depth := 0; depth < 16 && base != ""; depth++ {
		bc, ok := classes[base]
		if !ok {
			return authUnknown // base is a framework/3rd-party type we can't see
		}
		if bc.auth != authUnknown {
			return bc.auth
		}
		base = bc.base
	}
	return authUnknown
}

// dotnetBaseClass extracts the base class from a class declaration that starts
// at line idx: the first type after the top-level `:`, ignoring the primary
// constructor's (...) and any <generics>. Framework bases (Controller/
// ControllerBase/…) return "" since they carry no app auth.
func dotnetBaseClass(lines []string, idx int) string {
	var sb strings.Builder
	for i := idx; i < len(lines) && i < idx+16; i++ {
		if j := strings.IndexByte(lines[i], '{'); j >= 0 {
			sb.WriteString(lines[i][:j])
			break
		}
		sb.WriteString(lines[i])
		sb.WriteByte(' ')
	}
	header := sb.String()
	loc := reCsClass.FindStringSubmatchIndex(header)
	if loc == nil {
		return ""
	}
	rest := stripBalanced(stripBalanced(header[loc[1]:], '(', ')'), '<', '>')
	ci := strings.IndexByte(rest, ':')
	if ci < 0 {
		return ""
	}
	base := firstIdent(rest[ci+1:])
	switch base {
	case "Controller", "ControllerBase", "Object", "object", "PageModel", "ComponentBase":
		return ""
	}
	return base
}

// stripBalanced removes every top-level open..close balanced span (e.g. all
// (...) or all <...>) from s, leaving nested content out entirely.
func stripBalanced(s string, open, close byte) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case open:
			depth++
		case close:
			if depth > 0 {
				depth--
				continue
			}
			b.WriteByte(s[i])
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

// firstIdent returns the first C# identifier in s (skipping leading punctuation
// and whitespace).
func firstIdent(s string) string {
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		isIdent := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if isIdent && start < 0 {
			start = i
		} else if !isIdent && start >= 0 {
			return s[start:i]
		}
	}
	if start >= 0 {
		return s[start:]
	}
	return ""
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

// Signals of an app-wide authorization requirement. Each is deliberately
// specific so a single-endpoint `.RequireAuthorization()` can't masquerade as
// global auth — which would wrongly mark every endpoint authenticated and hide a
// real no-auth route (the worse error for a security tool).
var (
	reCsAuthorizeFilter  = regexp.MustCompile(`\bAuthorizeFilter\b`)                                  // MVC global filter
	reCsFallbackPolicy   = regexp.MustCompile(`\b(?:FallbackPolicy|DefaultPolicy)\b`)                 // applies to endpoints with no other metadata
	reCsRequireAuthed    = regexp.MustCompile(`\bRequireAuthenticatedUser\b`)                         // the policy actually demands a user
	reCsMapAll           = regexp.MustCompile(`\bMap(?:Controllers|RazorPages|DefaultControllerRoute|ControllerRoute|AreaControllerRoute)\b`)
	reCsMapAllAuthInline = regexp.MustCompile(`\bMap(?:Controllers|RazorPages|DefaultControllerRoute|ControllerRoute|AreaControllerRoute)\s*\([^)]*\)\s*\.\s*RequireAuthorization`)
	reCsRequireAuthLine  = regexp.MustCompile(`^\s*\.\s*RequireAuthorization\s*\(`)
)

// detectDotnetGlobalAuth reports whether the app enforces authentication
// globally, so an endpoint with no visible [Authorize] should still be treated
// as authenticated (only [AllowAnonymous] opts out). It recognises the three
// canonical forms — an MVC AuthorizeFilter, a Fallback/Default policy requiring
// an authenticated user, and RequireAuthorization() chained onto the whole
// controller/page endpoint set — including the split-startup case where these
// live in an extension file rather than Program.cs.
func detectDotnetGlobalAuth(files []scanner.TextFile) bool {
	for _, f := range files {
		if filepath.Ext(f.Path) != ".cs" {
			continue
		}
		var authorizeFilter, fallback, requiresAuthed bool
		for i, line := range f.Lines {
			switch {
			case reCsAuthorizeFilter.MatchString(line):
				authorizeFilter = true
			case reCsFallbackPolicy.MatchString(line):
				fallback = true
			}
			if reCsRequireAuthed.MatchString(line) {
				requiresAuthed = true
			}
			// MapControllers().RequireAuthorization() — inline or chained onto the
			// preceding MapControllers()/MapRazorPages() statement.
			if reCsMapAllAuthInline.MatchString(line) {
				return true
			}
			if reCsRequireAuthLine.MatchString(line) && prevStmtMapsAll(f.Lines, i) {
				return true
			}
		}
		if requiresAuthed && (authorizeFilter || fallback) {
			return true
		}
	}
	return false
}

// prevStmtMapsAll reports whether the nearest non-blank line above i maps the
// whole controller/page set — so a `.RequireAuthorization()` on its own line is
// attributed to MapControllers(), not to a single MapGet above it.
func prevStmtMapsAll(lines []string, i int) bool {
	for j := i - 1; j >= 0 && j >= i-3; j-- {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		return reCsMapAll.MatchString(lines[j])
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
