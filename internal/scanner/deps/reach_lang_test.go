package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonImportName(t *testing.T) {
	cases := map[string]string{
		"PyYAML":          "yaml",   // alias
		"Django":          "django", // lowercase
		"python-dateutil": "dateutil",
		"requests":        "requests",
		"scikit-learn":    "sklearn",
		"some-pkg":        "some_pkg", // default: lowercase + underscore
	}
	for in, want := range cases {
		if got := pythonImportName(in); got != want {
			t.Errorf("pythonImportName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPythonReach(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"),
		[]byte("import django\nfrom yaml import safe_load\n"), 0o644)
	refs := []pkgRef{
		{Name: "Django", Ecosystem: "PyPI"},
		{Name: "PyYAML", Ecosystem: "PyPI"},
		{Name: "Flask", Ecosystem: "PyPI"},
	}
	got := pythonReach(dir, nil, refs)
	if !got["Django"] || !got["PyYAML"] {
		t.Errorf("Django+PyYAML should be reachable, got %v", got)
	}
	if got["Flask"] {
		t.Error("Flask is not imported and must not be reachable")
	}
}

func TestGoReach(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\nimport (\n\t\"fmt\"\n\t\"github.com/gin-gonic/gin/binding\"\n)\n"
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644)
	refs := []pkgRef{
		{Name: "github.com/gin-gonic/gin", Ecosystem: "Go"}, // reached via subpackage
		{Name: "gopkg.in/yaml.v2", Ecosystem: "Go"},
	}
	got := goReach(dir, nil, refs)
	if !got["github.com/gin-gonic/gin"] {
		t.Error("gin should be reachable via its /binding subpackage")
	}
	if got["gopkg.in/yaml.v2"] {
		t.Error("yaml.v2 is not imported and must not be reachable")
	}
}
