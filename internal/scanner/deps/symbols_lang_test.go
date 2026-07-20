package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonSymbols(t *testing.T) {
	dir := t.TempDir()
	src := "from yaml import safe_load\nimport django\nx = django.setup()\n"
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644)
	got := pythonSymbols(dir, nil, []pkgRef{{Name: "PyYAML"}, {Name: "Django"}})
	if !has(got["PyYAML"], "safe_load") {
		t.Errorf("PyYAML symbols = %v, want safe_load", got["PyYAML"])
	}
	if !has(got["Django"], "setup") {
		t.Errorf("Django symbols = %v, want setup", got["Django"])
	}
}

func TestGoSymbols(t *testing.T) {
	dir := t.TempDir()
	src := "package main\nimport \"github.com/gin-gonic/gin\"\nfunc main(){ gin.Default(); gin.New() }\n"
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644)
	got := goSymbols(dir, nil, []pkgRef{{Name: "github.com/gin-gonic/gin"}})
	syms := got["github.com/gin-gonic/gin"]
	if !has(syms, "Default") || !has(syms, "New") {
		t.Errorf("gin symbols = %v, want Default+New", syms)
	}
}

func TestGoSymbols_Aliased(t *testing.T) {
	dir := t.TempDir()
	src := "package main\nimport g \"github.com/gin-gonic/gin\"\nfunc main(){ g.Default() }\n"
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644)
	got := goSymbols(dir, nil, []pkgRef{{Name: "github.com/gin-gonic/gin"}})
	if !has(got["github.com/gin-gonic/gin"], "Default") {
		t.Errorf("aliased import symbols = %v, want Default", got["github.com/gin-gonic/gin"])
	}
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
