package deps

import (
	"regexp"
	"strings"

	"github.com/malandas/andas/internal/scanner"
)

// This file extends andas's signature feature — import-level reachability —
// beyond JavaScript. A vulnerable package your source never imports is noise,
// in Python and Go just as in npm.

// --- Python ---

var rePyImport = regexp.MustCompile(`^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)`)

// pyAliases maps PyPI distribution names to the module you actually import,
// where they differ (the common offenders).
var pyAliases = map[string]string{
	"pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "pil",
	"scikit-learn": "sklearn", "python-dateutil": "dateutil",
	"opencv-python": "cv2", "pyjwt": "jwt", "python-dotenv": "dotenv",
	"msgpack-python": "msgpack", "protobuf": "google",
	"psycopg2-binary": "psycopg2", "mysqlclient": "mysqldb",
}

// pythonImportName derives the import module from a PyPI package name.
func pythonImportName(pkg string) string {
	low := strings.ToLower(pkg)
	if a, ok := pyAliases[low]; ok {
		return a
	}
	return strings.ReplaceAll(low, "-", "_")
}

func pythonImports(root string, ignore []string) map[string]bool {
	set := map[string]bool{}
	files, _ := scanner.WalkText(root, ignore)
	for _, f := range files {
		if !strings.HasSuffix(f.Path, ".py") {
			continue
		}
		for _, line := range f.Lines {
			if m := rePyImport.FindStringSubmatch(line); m != nil {
				set[strings.ToLower(m[1])] = true // top-level module, before any dot
			}
		}
	}
	return set
}

func pythonReach(root string, ignore []string, refs []pkgRef) map[string]bool {
	imported := pythonImports(root, ignore)
	out := map[string]bool{}
	for _, r := range refs {
		if imported[pythonImportName(r.Name)] {
			out[r.Name] = true
		}
	}
	return out
}

// --- Go ---

// goImports collects every import path referenced by the module's .go files.
func goImports(root string, ignore []string) map[string]bool {
	set := map[string]bool{}
	files, _ := scanner.WalkText(root, ignore)
	for _, f := range files {
		if !strings.HasSuffix(f.Path, ".go") {
			continue
		}
		inBlock := false
		for _, line := range f.Lines {
			t := strings.TrimSpace(line)
			switch {
			case inBlock:
				if t == ")" {
					inBlock = false
				} else if p := goQuoted(t); p != "" {
					set[p] = true
				}
			case t == "import (":
				inBlock = true
			case strings.HasPrefix(t, "import "):
				if p := goQuoted(t); p != "" {
					set[p] = true
				}
			}
		}
	}
	return set
}

// goReach marks a module reachable if any import path is that module or a
// package beneath it (Go import paths are the module path or a subpath of it).
func goReach(root string, ignore []string, refs []pkgRef) map[string]bool {
	paths := goImports(root, ignore)
	out := map[string]bool{}
	for _, r := range refs {
		for p := range paths {
			if p == r.Name || strings.HasPrefix(p, r.Name+"/") {
				out[r.Name] = true
				break
			}
		}
	}
	return out
}

func goQuoted(s string) string {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(s[i+1:], '"')
	if j < 0 {
		return ""
	}
	return s[i+1 : i+1+j]
}
