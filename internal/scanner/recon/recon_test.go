package recon

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, src string) string {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.js"), []byte(src), 0o644)
	return dir
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestHosts(t *testing.T) {
	dir := write(t, `db="postgres://10.0.3.14:5432/x"
cache="redis://cache.internal:6379"
fetch("http://169.254.169.254/")
public="https://api.stripe.com/v1"`)
	h := Hosts(dir, nil)
	for _, want := range []string{"10.0.3.14", "169.254.169.254", "cache.internal"} {
		if !has(h, want) {
			t.Errorf("internal host %q not found in %v", want, h)
		}
	}
	if has(h, "api.stripe.com") {
		t.Error("a public host must not be listed as internal")
	}
}

func TestParams(t *testing.T) {
	dir := write(t, "lookup(req.query.role, req.params.id); auth(req.body.username)")
	p := Params(dir, nil)
	for _, want := range []string{"role", "id", "username"} {
		if !has(p, want) {
			t.Errorf("param %q not extracted from %v", want, p)
		}
	}
}
