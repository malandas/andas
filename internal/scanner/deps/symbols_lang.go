package deps

import (
	"regexp"
	"sort"
	"strings"
)

// Function-level evidence for Python and Go: which exports of a vulnerable
// package your code actually calls. Like the JS version, this is triage
// evidence only — never an automatic downgrade, since mapping an advisory to
// exact functions is unreliable and a false "safe" is worse than a false alarm.

func finalizeSyms(acc map[string]map[string]bool) map[string][]string {
	out := map[string][]string{}
	for pkg, set := range acc {
		syms := make([]string, 0, len(set))
		for s := range set {
			syms = append(syms, s)
		}
		sort.Strings(syms)
		out[pkg] = syms
	}
	return out
}

func firstSeg(dotted string) string {
	if i := strings.IndexByte(dotted, '.'); i >= 0 {
		return dotted[:i]
	}
	return dotted
}

func lastSeg(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// --- Python ---

var (
	rePyFrom     = regexp.MustCompile(`^\s*from\s+([\w.]+)\s+import\s+(.+)`)
	rePyImportAs = regexp.MustCompile(`^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?`)
)

func pyName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "()")
	if i := strings.Index(s, " as "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func pythonSymbols(root string, ignore []string, wanted []pkgRef) map[string][]string {
	modToPkg := map[string]string{}
	for _, r := range wanted {
		modToPkg[pythonImportName(r.Name)] = r.Name
	}
	acc := map[string]map[string]bool{}
	add := func(pkg, sym string) {
		if pkg == "" || sym == "" || sym == "*" {
			return
		}
		if acc[pkg] == nil {
			acc[pkg] = map[string]bool{}
		}
		acc[pkg][sym] = true
	}
	for _, f := range langFiles(root, ignore, ".py") {
		content := strings.Join(f.Lines, "\n")
		bindings := map[string]string{}
		for _, line := range f.Lines {
			if m := rePyFrom.FindStringSubmatch(line); m != nil {
				if pkg, ok := modToPkg[strings.ToLower(firstSeg(m[1]))]; ok {
					for _, name := range strings.Split(m[2], ",") {
						add(pkg, pyName(name))
					}
				}
			} else if m := rePyImportAs.FindStringSubmatch(line); m != nil {
				if pkg, ok := modToPkg[strings.ToLower(firstSeg(m[1]))]; ok {
					local := m[2]
					if local == "" {
						local = firstSeg(m[1])
					}
					bindings[local] = pkg
				}
			}
		}
		for local, pkg := range bindings {
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(local) + `\.([A-Za-z_]\w*)`)
			for _, m := range re.FindAllStringSubmatch(content, -1) {
				add(pkg, m[1])
			}
		}
	}
	return finalizeSyms(acc)
}

// --- Go ---

func goSymbols(root string, ignore []string, wanted []pkgRef) map[string][]string {
	acc := map[string]map[string]bool{}
	add := func(pkg, sym string) {
		if pkg == "" || sym == "" {
			return
		}
		if acc[pkg] == nil {
			acc[pkg] = map[string]bool{}
		}
		acc[pkg][sym] = true
	}
	for _, f := range langFiles(root, ignore, ".go") {
		content := strings.Join(f.Lines, "\n")
		bindings := map[string]string{} // local package name -> module
		for path, alias := range goImportBindings(f.Lines) {
			for _, r := range wanted {
				if path == r.Name || strings.HasPrefix(path, r.Name+"/") {
					local := alias
					if local == "" {
						local = lastSeg(path)
					}
					bindings[local] = r.Name
				}
			}
		}
		for local, pkg := range bindings {
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(local) + `\.([A-Z]\w*)`)
			for _, m := range re.FindAllStringSubmatch(content, -1) {
				add(pkg, m[1])
			}
		}
	}
	return finalizeSyms(acc)
}

// goImportBindings returns import path -> alias ("" when none) for one file.
var reGoImportLine = regexp.MustCompile(`^\s*(?:(\w+|\.)\s+)?"([^"]+)"`)

func goImportBindings(lines []string) map[string]string {
	out := map[string]string{}
	inBlock := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case inBlock:
			if t == ")" {
				inBlock = false
			} else if m := reGoImportLine.FindStringSubmatch(t); m != nil {
				out[m[2]] = m[1]
			}
		case t == "import (":
			inBlock = true
		case strings.HasPrefix(t, "import "):
			if m := reGoImportLine.FindStringSubmatch(strings.TrimPrefix(t, "import ")); m != nil {
				out[m[2]] = m[1]
			}
		}
	}
	return out
}
