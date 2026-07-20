package deps

import (
	"regexp"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/scanner"
)

// jsFile reports whether a path is JS/TS source we should scan for imports.
func jsFile(path string) bool {
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// reImport captures the module specifier from the common module syntaxes:
//
//	import x from 'pkg'   ·   require('pkg')   ·   import('pkg')   ·   import 'pkg'
var reImport = regexp.MustCompile(`(?:from|require\(|import\()\s*['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"]`)

// importedPackages walks the source tree under root and returns the set of
// bare package names it imports (local "./" and absolute imports excluded).
func importedPackages(root string) (map[string]bool, error) {
	files, err := scanner.WalkText(root)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, f := range files {
		if !jsFile(f.Path) {
			continue
		}
		for _, line := range f.Lines {
			for _, m := range reImport.FindAllStringSubmatch(line, -1) {
				spec := m[1]
				if spec == "" {
					spec = m[2]
				}
				if name := specifierToPackage(spec); name != "" {
					set[name] = true
				}
			}
		}
	}
	return set, nil
}

// specifierToPackage maps an import specifier to the npm package it belongs to,
// or "" for local/relative imports. "lodash/fp" -> "lodash";
// "@react-navigation/native/x" -> "@react-navigation/native".
func specifierToPackage(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return ""
	}
	return parts[0]
}

// Symbol extraction: which exports of a package the app actually touches. This
// is the first, deliberately conservative step toward function-level
// reachability — evidence for a human, never an automatic downgrade.
var (
	// import { a, b as c } from 'pkg'   — captures the braced names + specifier
	reNamed = regexp.MustCompile(`import\s+(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]`)
	// import _ from 'pkg'  ·  import * as _ from 'pkg'  — captures binding + spec
	reDefault = regexp.MustCompile(`import\s+(?:\*\s+as\s+)?([\w$]+)\s*(?:,\s*\{[^}]*\})?\s*from\s*['"]([^'"]+)['"]`)
	// const _ = require('pkg')  — captures binding + spec
	reRequire = regexp.MustCompile(`(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['"]([^'"]+)['"]`)
	// const { a, b } = require('pkg')  — captures braced names + spec
	reReqDestr = regexp.MustCompile(`(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]`)
)

// usedSymbols returns, for each package in `wanted`, the sorted set of exported
// symbols the app's source appears to use. Named imports are taken directly;
// for a default/namespace binding it finds `binding.member` accesses across the
// same file.
func usedSymbols(root string, wanted map[string]bool) (map[string][]string, error) {
	files, err := scanner.WalkText(root)
	if err != nil {
		return nil, err
	}
	acc := map[string]map[string]bool{} // pkg -> set of symbols

	add := func(pkgName, sym string) {
		if !wanted[pkgName] || sym == "" {
			return
		}
		if acc[pkgName] == nil {
			acc[pkgName] = map[string]bool{}
		}
		acc[pkgName][sym] = true
	}

	for _, f := range files {
		if !jsFile(f.Path) {
			continue
		}
		content := strings.Join(f.Lines, "\n")

		// Named imports / destructured requires → symbols are explicit.
		for _, re := range []*regexp.Regexp{reNamed, reReqDestr} {
			for _, m := range re.FindAllStringSubmatch(content, -1) {
				pkgName := specifierToPackage(m[2])
				for _, name := range strings.Split(m[1], ",") {
					add(pkgName, importedName(name))
				}
			}
		}

		// Default/namespace/require bindings → resolve member accesses.
		bindings := map[string]string{} // localName -> package
		for _, re := range []*regexp.Regexp{reDefault, reRequire} {
			for _, m := range re.FindAllStringSubmatch(content, -1) {
				if pkgName := specifierToPackage(m[2]); wanted[pkgName] {
					bindings[m[1]] = pkgName
				}
			}
		}
		for local, pkgName := range bindings {
			reMember := regexp.MustCompile(`\b` + regexp.QuoteMeta(local) + `\.([\w$]+)`)
			for _, m := range reMember.FindAllStringSubmatch(content, -1) {
				add(pkgName, m[1])
			}
		}
	}

	out := map[string][]string{}
	for pkgName, set := range acc {
		syms := make([]string, 0, len(set))
		for s := range set {
			syms = append(syms, s)
		}
		sort.Strings(syms)
		out[pkgName] = syms
	}
	return out, nil
}

// importedName pulls the source export name from a specifier list entry,
// dropping any `as alias` and surrounding whitespace. "b as c" -> "b".
func importedName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " as "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// reachableSet returns every package reachable in the dependency graph starting
// from the packages the app actually imports. This is the heart of the vuln
// module: a vulnerable package outside this set is present but untouched — noise.
func reachableSet(g *graph, roots map[string]bool) map[string]bool {
	reached := map[string]bool{}
	queue := make([]string, 0, len(roots))
	for name := range roots {
		if _, known := g.byName[name]; known || g.direct[name] {
			if !reached[name] {
				reached[name] = true
				queue = append(queue, name)
			}
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		p := g.byName[name]
		if p == nil {
			continue
		}
		for _, dep := range p.Deps {
			if !reached[dep] {
				reached[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	return reached
}
