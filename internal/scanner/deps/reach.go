package deps

import (
	"regexp"
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
