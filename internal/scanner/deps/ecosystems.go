package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// This file makes andas multi-language. Each ecosystem contributes a manifest
// name and a parser that resolves it to pkgRefs; deps.Scan queries OSV for all
// of them. Reachability analysis stays JS-only for now — other ecosystems get
// vulnerability findings ranked by real severity, which is already a big cut
// over an unranked audit.

type ecosystem struct {
	name     string // human label, e.g. "Python"
	manifest string // file to look for, e.g. "requirements.txt"
	parse    func(path string) []pkgRef
	// reach optionally returns which of refs your source actually imports; nil
	// means reachability isn't analysed for this ecosystem yet.
	reach func(root string, ignore []string, refs []pkgRef) map[string]bool
	// symbols optionally returns which exports of each package the code calls,
	// keyed by package name — triage evidence, never an auto-downgrade.
	symbols func(root string, ignore []string, wanted []pkgRef) map[string][]string
}

var ecosystems = []ecosystem{
	{"Python", "requirements.txt", parseRequirements, pythonReach, pythonSymbols},
	{"Go", "go.mod", parseGoMod, goReach, goSymbols},
	{"Ruby", "Gemfile.lock", parseGemfileLock, rubyReach, nil},
	{"Rust", "Cargo.lock", parseCargoLock, rustReach, nil},
	{"PHP", "composer.lock", parseComposerLock, phpReach, nil},
}

// findManifest returns the shallowest manifest of the given name under root.
func findManifest(root, name string) string {
	best, bestDepth := "", 1<<30
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipVendorDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == name {
			if depth := strings.Count(path, string(os.PathSeparator)); depth < bestDepth {
				best, bestDepth = path, depth
			}
		}
		return nil
	})
	return best
}

var skipVendorDir = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, ".venv": true, "venv": true,
	"site-packages": true, "target": true, "dist": true, "build": true,
}

// --- Python: requirements.txt, pinned "pkg==1.2.3" lines only ---

var reReq = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][0-9A-Za-z.\-+!]*)`)

func parseRequirements(path string) []pkgRef {
	var out []pkgRef
	for _, line := range readLines(path) {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if m := reReq.FindStringSubmatch(line); m != nil {
			out = append(out, pkgRef{Name: m[1], Version: m[2], Ecosystem: "PyPI"})
		}
	}
	return out
}

// --- Go: go.mod require lines ---

var reGoReq = regexp.MustCompile(`^\s*([^\s()]+/[^\s()]+)\s+v([0-9][0-9A-Za-z.\-+]*)`)

func parseGoMod(path string) []pkgRef {
	var out []pkgRef
	for _, line := range readLines(path) {
		line = strings.TrimPrefix(strings.TrimSpace(line), "require ")
		if strings.HasSuffix(line, "// indirect") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "// indirect"))
		}
		if m := reGoReq.FindStringSubmatch(line); m != nil {
			out = append(out, pkgRef{Name: m[1], Version: m[2], Ecosystem: "Go"})
		}
	}
	return out
}

// --- Ruby: Gemfile.lock, the "specs:" section "name (1.2.3)" ---

var reGem = regexp.MustCompile(`^\s{4}([A-Za-z0-9._-]+) \(([0-9][0-9A-Za-z.\-]*)\)`)

func parseGemfileLock(path string) []pkgRef {
	var out []pkgRef
	for _, line := range readLines(path) {
		if m := reGem.FindStringSubmatch(line); m != nil {
			out = append(out, pkgRef{Name: m[1], Version: m[2], Ecosystem: "RubyGems"})
		}
	}
	return out
}

// --- Rust: Cargo.lock, [[package]] blocks with name/version ---

func parseCargoLock(path string) []pkgRef {
	var out []pkgRef
	var name string
	for _, line := range readLines(path) {
		line = strings.TrimSpace(line)
		switch {
		case line == "[[package]]":
			name = ""
		case strings.HasPrefix(line, "name = "):
			name = tomlString(line)
		case strings.HasPrefix(line, "version = ") && name != "":
			out = append(out, pkgRef{Name: name, Version: tomlString(line), Ecosystem: "crates.io"})
			name = ""
		}
	}
	return out
}

// --- PHP: composer.lock, JSON "packages":[{name,version}] ---

func parseComposerLock(path string) []pkgRef {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []pkgRef
	for _, p := range lock.Packages {
		out = append(out, pkgRef{
			Name:      p.Name,
			Version:   strings.TrimPrefix(p.Version, "v"),
			Ecosystem: "Packagist",
		})
	}
	return out
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

func tomlString(line string) string {
	if i := strings.IndexByte(line, '"'); i >= 0 {
		if j := strings.IndexByte(line[i+1:], '"'); j >= 0 {
			return line[i+1 : i+1+j]
		}
	}
	return ""
}
