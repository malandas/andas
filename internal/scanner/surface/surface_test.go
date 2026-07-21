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
