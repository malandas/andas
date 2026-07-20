package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/malandas/andas/internal/scanner"
)

// Reachability for Ruby, Rust, and PHP — completing the matrix. Each language's
// import mechanism differs, and each has a trap that would cause a *false* "safe"
// (worse than a false alarm), so each is handled conservatively.

// --- Ruby ---
//
// Trap: Rails/Bundler call `Bundler.require`, which auto-loads every gem in the
// Gemfile — so a gem can be used without an explicit `require`. If we see that,
// we treat all gems as reachable rather than risk demoting one that's really in
// use. Only plain projects with explicit requires get reachability filtering.

var reRubyRequire = regexp.MustCompile(`require(?:_relative)?\s*\(?\s*['"]([^'"]+)['"]`)

func rubyReach(root string, ignore []string, refs []pkgRef) map[string]bool {
	files := langFiles(root, ignore, ".rb")
	out := map[string]bool{}
	required := map[string]bool{}
	bundlerAuto := false
	for _, f := range files {
		body := strings.Join(f.Lines, "\n")
		if strings.Contains(body, "Bundler.require") {
			bundlerAuto = true
		}
		for _, m := range reRubyRequire.FindAllStringSubmatch(body, -1) {
			required[m[1]] = true
			if i := strings.IndexByte(m[1], '/'); i > 0 {
				required[m[1][:i]] = true // "active_support/all" -> "active_support"
			}
		}
	}
	if bundlerAuto {
		for _, r := range refs {
			out[r.Name] = true // can't safely demote under Bundler.require
		}
		return out
	}
	for _, r := range refs {
		// Match liberally to avoid false "unreachable": gem name, or with '-'
		// swapped for the require conventions.
		for _, cand := range []string{r.Name, strings.ReplaceAll(r.Name, "-", "/"), strings.ReplaceAll(r.Name, "-", "_")} {
			if required[cand] {
				out[r.Name] = true
				break
			}
		}
	}
	return out
}

// --- Rust ---
//
// Cargo.lock uses hyphens; source refers to crates with underscores
// (`use serde_json::...`). Match on the underscored name.

var (
	reRustUse    = regexp.MustCompile(`^\s*use\s+([a-zA-Z_][a-zA-Z0-9_]*)`)
	reRustExtern = regexp.MustCompile(`extern\s+crate\s+([a-zA-Z_][a-zA-Z0-9_]*)`)
)

func rustReach(root string, ignore []string, refs []pkgRef) map[string]bool {
	imported := map[string]bool{}
	for _, f := range langFiles(root, ignore, ".rs") {
		for _, line := range f.Lines {
			if m := reRustUse.FindStringSubmatch(line); m != nil {
				imported[m[1]] = true
			}
			if m := reRustExtern.FindStringSubmatch(line); m != nil {
				imported[m[1]] = true
			}
		}
	}
	out := map[string]bool{}
	for _, r := range refs {
		if imported[strings.ReplaceAll(r.Name, "-", "_")] {
			out[r.Name] = true
		}
	}
	return out
}

// --- PHP ---
//
// PHP autoloading is lazy: a package is only used if its namespace is actually
// referenced. composer.lock carries each package's PSR-4 namespaces, so we map
// namespace -> package from the lockfile itself, then match `use Ns\...` in code.

var rePhpUse = regexp.MustCompile(`\buse\s+\\?([A-Za-z_][A-Za-z0-9_]*)`)

func phpReach(root string, ignore []string, refs []pkgRef) map[string]bool {
	nsToPkg := phpNamespaceMap(findManifest(root, "composer.lock"))
	referenced := map[string]bool{}
	for _, f := range langFiles(root, ignore, ".php") {
		for _, line := range f.Lines {
			if m := rePhpUse.FindStringSubmatch(line); m != nil {
				referenced[m[1]] = true
			}
		}
	}
	out := map[string]bool{}
	for ns, pkg := range nsToPkg {
		if referenced[ns] {
			out[pkg] = true
		}
	}
	return out
}

// phpNamespaceMap reads composer.lock and returns root-namespace -> package.
func phpNamespaceMap(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages []struct {
			Name     string `json:"name"`
			Autoload struct {
				Psr4 map[string]json.RawMessage `json:"psr-4"`
				Psr0 map[string]json.RawMessage `json:"psr-0"`
			} `json:"autoload"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	out := map[string]string{}
	for _, p := range lock.Packages {
		for ns := range p.Autoload.Psr4 {
			out[rootNamespace(ns)] = p.Name
		}
		for ns := range p.Autoload.Psr0 {
			out[rootNamespace(ns)] = p.Name
		}
	}
	return out
}

func rootNamespace(ns string) string {
	ns = strings.Trim(ns, `\`)
	if i := strings.IndexByte(ns, '\\'); i >= 0 {
		return ns[:i]
	}
	return ns
}

// langFiles returns the text files under root with the given extension.
func langFiles(root string, ignore []string, ext string) []scanner.TextFile {
	all, _ := scanner.WalkText(root, ignore)
	var out []scanner.TextFile
	for _, f := range all {
		if filepath.Ext(f.Path) == ext {
			out = append(out, f)
		}
	}
	return out
}
