package deps

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestSpecifierToPackage(t *testing.T) {
	cases := map[string]string{
		"lodash":                        "lodash",
		"lodash/fp":                     "lodash",
		"@react-navigation/native":      "@react-navigation/native",
		"@react-navigation/native/dist": "@react-navigation/native",
		"./local":                       "",
		"../up":                         "",
		"/abs":                          "",
	}
	for in, want := range cases {
		if got := specifierToPackage(in); got != want {
			t.Errorf("specifierToPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDescriptorName(t *testing.T) {
	cases := map[string]string{
		"lodash@^4.17.11":        "lodash",
		"\"@babel/core@^7.0.0\"": "@babel/core",
		"lodash@npm:^4.17.11":    "lodash",
		"@babel/core@npm:^7.0.0": "@babel/core",
	}
	for in, want := range cases {
		if got := descriptorName(in); got != want {
			t.Errorf("descriptorName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseYarnLock_Classic(t *testing.T) {
	lock := []byte(`# yarn lockfile v1

lodash@^4.17.11:
  version "4.17.11"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.11.tgz#hash"

handlebars@^4.0.11:
  version "4.0.11"
  dependencies:
    async "^1.4.0"
`)
	got := parseYarnLock(lock)
	if got["lodash"] == nil || got["lodash"].Version != "4.17.11" {
		t.Fatalf("lodash not parsed correctly: %+v", got["lodash"])
	}
	if h := got["handlebars"]; h == nil || len(h.Deps) != 1 || h.Deps[0] != "async" {
		t.Fatalf("handlebars deps not parsed: %+v", h)
	}
}

func TestParseYarnLock_Berry(t *testing.T) {
	lock := []byte(`# yarn Berry

__metadata:
  version: 6

"lodash@npm:^4.17.11":
  version: 4.17.11
  resolution: "lodash@npm:4.17.11"

"handlebars@npm:^4.0.11":
  version: 4.0.11
  dependencies:
    async: "npm:^1.4.0"
`)
	got := parseYarnLock(lock)
	if _, ok := got["__metadata"]; ok {
		t.Error("__metadata should not be treated as a package")
	}
	if got["lodash"] == nil || got["lodash"].Version != "4.17.11" {
		t.Fatalf("Berry lodash not parsed: %+v", got["lodash"])
	}
	if h := got["handlebars"]; h == nil || len(h.Deps) != 1 || h.Deps[0] != "async" {
		t.Fatalf("Berry handlebars deps not parsed: %+v", h)
	}
}

func TestReachableSet(t *testing.T) {
	// A -> B -> C ; D is isolated. Importing only A should reach A, B, C.
	g := &graph{
		byName: map[string]*pkg{
			"A": {Name: "A", Deps: []string{"B"}},
			"B": {Name: "B", Deps: []string{"C"}},
			"C": {Name: "C"},
			"D": {Name: "D"},
		},
		direct: map[string]bool{"A": true, "D": true},
	}
	got := reachableSet(g, map[string]bool{"A": true})
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	if want := []string{"A", "B", "C"}; !reflect.DeepEqual(names, want) {
		t.Errorf("reachableSet = %v, want %v (D must stay unreachable)", names, want)
	}
}

func TestImportedName(t *testing.T) {
	cases := map[string]string{
		"merge":        "merge",
		"  template  ": "template",
		"b as c":       "b",
	}
	for in, want := range cases {
		if got := importedName(in); got != want {
			t.Errorf("importedName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImportedPackagesAndSymbols(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"import _ from 'lodash';\n" +
		"import { readFile } from 'fs-extra';\n" +
		"import './local';\n" +
		"const x = _.merge({}, _.template);\n" +
		"require('axios');\n"
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	imports, err := importedPackages(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lodash", "fs-extra", "axios"} {
		if !imports[want] {
			t.Errorf("importedPackages missing %q (got %v)", want, imports)
		}
	}
	if imports["local"] || imports[""] {
		t.Error("relative import leaked into the package set")
	}

	syms, err := usedSymbols(dir, map[string]bool{"lodash": true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range syms["lodash"] {
		got[s] = true
	}
	if !got["merge"] || !got["template"] {
		t.Errorf("usedSymbols(lodash) = %v, want merge+template", syms["lodash"])
	}
}
