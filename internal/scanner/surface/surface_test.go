package surface

import (
	"os"
	"path/filepath"
	"testing"
)

func mapDir(t *testing.T, name, src string) []Route {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Map(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(rs []Route, method, path string) *Route {
	for i := range rs {
		if rs[i].Method == method && rs[i].Path == path {
			return &rs[i]
		}
	}
	return nil
}

func TestSurface_ExpressAuthAndInput(t *testing.T) {
	src := "const auth = require('./auth')\n" +
		"app.get('/health', (req,res)=>ok())\n" +
		"app.post('/api/exec', (req,res)=>run(req.body.cmd))\n" +
		"app.get('/admin', auth.requireAuth, (req,res)=>x())\n"
	rs := mapDir(t, "r.js", src)
	if r := find(rs, "GET", "/admin"); r == nil || !r.Auth {
		t.Errorf("/admin should be authed (inline middleware): %+v", r)
	}
	if r := find(rs, "POST", "/api/exec"); r == nil || r.Auth || !r.UserInput {
		t.Errorf("/api/exec should be no-auth + input: %+v", r)
	}
	if r := find(rs, "GET", "/health"); r == nil || r.Auth {
		t.Errorf("/health should be no-auth (an unrelated require('auth') must not count): %+v", r)
	}
}

func TestSurface_FlaskDecoratorAuth(t *testing.T) {
	src := "@app.route('/profile', methods=['GET'])\n@login_required\ndef profile(): pass\n\n" +
		"@app.post('/upload')\ndef upload(): return save(request.files['f'])\n"
	rs := mapDir(t, "v.py", src)
	if r := find(rs, "ANY", "/profile"); r == nil || !r.Auth {
		t.Errorf("/profile should be authed via @login_required: %+v", r)
	}
	if r := find(rs, "POST", "/upload"); r == nil || r.Auth {
		t.Errorf("/upload should be no-auth: %+v", r)
	}
}

func TestSurface_GoAndLaravel(t *testing.T) {
	if r := find(mapDir(t, "m.go", `r.POST("/api/x", h)`), "POST", "/api/x"); r == nil {
		t.Error("Gin route not detected")
	}
	if r := find(mapDir(t, "web.php", `Route::get('/dash', 'C@i');`), "GET", "/dash"); r == nil {
		t.Error("Laravel route not detected")
	}
}

func TestSurface_GoFrameworks(t *testing.T) {
	src := "r.GET(\"/api/a\", h)\ne.POST(\"/api/b\", h)\nhttp.HandleFunc(\"/c\", h)\nr.Get(\"/d\", h)\n"
	rs := mapDir(t, "m.go", src)
	for _, want := range []struct{ m, p string }{{"GET", "/api/a"}, {"POST", "/api/b"}, {"GET", "/c"}, {"GET", "/d"}} {
		if find(rs, want.m, want.p) == nil {
			t.Errorf("Go route %s %s not detected", want.m, want.p)
		}
	}
}

func TestSurface_RailsResources(t *testing.T) {
	rs := mapDir(t, "routes.rb", "resources :posts\n")
	for _, want := range []struct{ m, p string }{{"GET", "/posts"}, {"POST", "/posts"}, {"GET", "/posts/:id"}, {"DELETE", "/posts/:id"}} {
		if find(rs, want.m, want.p) == nil {
			t.Errorf("resources expansion missing %s %s", want.m, want.p)
		}
	}
}

func TestSurface_GraphQL(t *testing.T) {
	src := "type Query {\n  users(id: ID): [User]\n}\ntype Mutation {\n  del(id: ID!): Boolean\n}\n"
	rs := mapDir(t, "s.graphql", src)
	if find(rs, "QUERY", "/graphql#users") == nil || find(rs, "MUTATION", "/graphql#del") == nil {
		t.Errorf("graphql ops not extracted: %+v", rs)
	}
}

func TestSurface_OpenAPI(t *testing.T) {
	src := "openapi: 3.0.0\npaths:\n  /api/x:\n    get:\n      summary: a\n    post:\n      summary: b\n"
	rs := mapDir(t, "api.yaml", src)
	if find(rs, "GET", "/api/x") == nil || find(rs, "POST", "/api/x") == nil {
		t.Errorf("openapi paths not extracted: %+v", rs)
	}
}

func TestSurface_RateLimitInline(t *testing.T) {
	rs := mapDir(t, "r.js", "app.post('/api/login', limiter, h)\napp.post('/api/reset', h)\n")
	if r := find(rs, "POST", "/api/login"); r == nil || !r.RateLimited {
		t.Errorf("/api/login has inline limiter, want RateLimited: %+v", r)
	}
	if r := find(rs, "POST", "/api/reset"); r == nil || r.RateLimited {
		t.Errorf("/api/reset has no limiter, want RateLimited=false: %+v", r)
	}
}

// mapFiles writes several files into one temp dir and maps them together — used
// to exercise cross-file behaviour like the global auth-policy detector.
func mapFiles(t *testing.T, files map[string]string) []Route {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Map(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSurface_DotnetAttributeRouting(t *testing.T) {
	src := "namespace App.Controllers;\n" +
		"[Route(\"departments/{id:guid}\")]\n" +
		"[Authorize]\n" +
		"public class DepartmentsController : Controller\n" +
		"{\n" +
		"    [HttpGet(\"goals\")]\n" +
		"    public IActionResult Goals(Guid id) => View();\n" +
		"    [HttpPost(\"goals/create\")]\n" +
		"    public IActionResult Create(Guid id) => View();\n" +
		"}\n"
	rs := mapDir(t, "DepartmentsController.cs", src)
	// Controller prefix + action path combine; constraint {id:guid} -> {id}.
	if r := find(rs, "GET", "/departments/{id}/goals"); r == nil {
		t.Fatalf("prefix+action not combined; got %+v", rs)
	} else if !r.Auth {
		t.Errorf("[Authorize] on controller should mark action authed: %+v", r)
	}
	// POST + route param means user input.
	if r := find(rs, "POST", "/departments/{id}/goals/create"); r == nil || !r.UserInput {
		t.Errorf("POST action missing or not flagged UserInput: %+v", r)
	}
}

func TestSurface_DotnetAbsolutePathAndAllowAnonymous(t *testing.T) {
	src := "namespace App.Controllers;\n" +
		"[AllowAnonymous]\n" +
		"public class HealthController : Controller\n" +
		"{\n" +
		"    [HttpGet(\"/healthz\")] public IActionResult Live() => Ok();\n" +
		"}\n"
	rs := mapDir(t, "HealthController.cs", src)
	// A leading '/' is an absolute route — the controller prefix is ignored.
	r := find(rs, "GET", "/healthz")
	if r == nil {
		t.Fatalf("absolute route /healthz not found; got %+v", rs)
	}
	if r.Auth {
		t.Errorf("[AllowAnonymous] controller should not be authed: %+v", r)
	}
}

func TestSurface_DotnetGlobalAuthPolicy(t *testing.T) {
	program := "var b = WebApplication.CreateBuilder();\n" +
		"b.Services.AddControllersWithViews(o => {\n" +
		"  var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();\n" +
		"  o.Filters.Add(new AuthorizeFilter(policy));\n" +
		"});\n"
	controller := "namespace App.Controllers;\n" +
		"[Route(\"reviews\")]\n" +
		"public class ReviewsController : Controller\n" +
		"{\n" +
		"    [HttpGet(\"\")] public IActionResult Index() => View();\n" +
		"    [AllowAnonymous][HttpGet(\"public\")] public IActionResult Pub() => View();\n" +
		"}\n"
	rs := mapFiles(t, map[string]string{"Program.cs": program, "ReviewsController.cs": controller})

	// With a global AuthorizeFilter, a controller with no [Authorize] is still authed.
	if r := find(rs, "GET", "/reviews"); r == nil || !r.Auth {
		t.Errorf("global auth filter should mark /reviews authed: %+v", r)
	}
	// ...but an explicit [AllowAnonymous] action still opts out.
	if r := find(rs, "GET", "/reviews/public"); r == nil || r.Auth {
		t.Errorf("[AllowAnonymous] action should stay unauthed despite global filter: %+v", r)
	}
}

func TestSurface_DotnetMinimalApi(t *testing.T) {
	src := "var app = WebApplication.Create();\n" +
		"app.MapGet(\"/api/ping\", () => \"pong\");\n" +
		"app.MapPost(\"/api/users\", (User u) => Results.Ok()).RequireAuthorization();\n"
	rs := mapDir(t, "Program.cs", src)
	if find(rs, "GET", "/api/ping") == nil {
		t.Errorf("minimal API MapGet not found: %+v", rs)
	}
	if r := find(rs, "POST", "/api/users"); r == nil || !r.Auth {
		t.Errorf("MapPost with .RequireAuthorization() should be authed: %+v", r)
	}
}
