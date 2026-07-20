package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// pkg is one resolved package in the dependency graph.
type pkg struct {
	Name    string
	Version string
	Dev     bool
	Deps    []string // names this package depends on (graph edges)
}

// graph is the resolved dependency universe for a project.
type graph struct {
	byName map[string]*pkg // resolved package by name
	direct map[string]bool // names listed in the app's own dependencies
}

// packageJSON is the slice of package.json we care about.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// lockJSON models npm's lockfile v2/v3 "packages" map, which conveniently
// carries resolved versions, the dev flag, and dependency edges all at once.
type lockJSON struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version      string            `json:"version"`
		Dev          bool              `json:"dev"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"packages"`
}

// loadGraph reads package.json (required) plus whichever lockfile is present in
// projDir (package-lock.json preferred, then yarn.lock) and builds the resolved
// dependency graph. Without a lockfile it falls back to the direct dependencies
// only, with versions stripped of range prefixes — enough to query OSV, but
// without transitive edges. lockKind reports which source was used.
func loadGraph(pkgJSONPath, projDir string) (g *graph, lockKind string, err error) {
	raw, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return nil, "", err
	}
	var pj packageJSON
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil, "", err
	}

	g = &graph{byName: map[string]*pkg{}, direct: map[string]bool{}}
	devSet := map[string]bool{}
	for name := range pj.Dependencies {
		g.direct[name] = true
	}
	for name := range pj.DevDependencies {
		if !g.direct[name] {
			devSet[name] = true
		}
	}

	// Prefer npm's lockfile: it carries versions, edges, and a dev flag.
	if lockRaw, err := os.ReadFile(filepath.Join(projDir, "package-lock.json")); err == nil {
		var lf lockJSON
		if json.Unmarshal(lockRaw, &lf) == nil && len(lf.Packages) > 0 {
			for key, p := range lf.Packages {
				name := packageName(key)
				if name == "" || p.Version == "" {
					continue
				}
				deps := make([]string, 0, len(p.Dependencies))
				for d := range p.Dependencies {
					deps = append(deps, d)
				}
				// Last write wins on duplicate names (nested versions); a
				// known v1 simplification we accept for now.
				g.byName[name] = &pkg{Name: name, Version: p.Version, Dev: p.Dev, Deps: deps}
			}
			return g, "package-lock.json", nil
		}
	}

	// Otherwise yarn.lock. It has versions and edges but no dev flag, so we
	// mark packages dev from package.json's devDependencies.
	if yarnRaw, err := os.ReadFile(filepath.Join(projDir, "yarn.lock")); err == nil {
		if pkgs := parseYarnLock(yarnRaw); len(pkgs) > 0 {
			for name, p := range pkgs {
				p.Dev = devSet[name]
				g.byName[name] = p
			}
			return g, "yarn.lock", nil
		}
	}

	// Fallback: no usable lockfile. Use declared ranges as best-effort.
	for name, ver := range pj.Dependencies {
		g.byName[name] = &pkg{Name: name, Version: cleanVersion(ver)}
	}
	for name, ver := range pj.DevDependencies {
		if _, ok := g.byName[name]; !ok {
			g.byName[name] = &pkg{Name: name, Version: cleanVersion(ver), Dev: true}
		}
	}
	return g, "package.json (no lockfile)", nil
}

// packageName extracts the package name from a lockfile key like
// "node_modules/foo" or "node_modules/foo/node_modules/@scope/bar".
func packageName(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return "" // the "" root entry, or an unexpected key
	}
	return key[i+len(marker):]
}

// cleanVersion strips npm range operators to leave a bare version for OSV.
func cleanVersion(v string) string {
	return strings.TrimLeft(strings.TrimSpace(v), "^~>=<v ")
}
