// Package deps scans JavaScript/TypeScript projects for vulnerable npm
// dependencies and — andas's differentiator — decides whether each vulnerable
// package is actually reachable from the app's own code before ranking it.
package deps

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "deps" }

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	if opts.Offline {
		if hasAnyManifest(root) {
			fmt.Fprintln(os.Stderr, "andas: offline mode — skipping OSV vulnerability lookup")
		}
		return nil, nil
	}

	var out []finding.Finding

	// JavaScript/TypeScript gets the rich path: reachability + used-symbol
	// evidence. Every other ecosystem gets vulnerability findings ranked by
	// real severity (reachability not yet analysed for those languages).
	if pkgJSONPath := findPackageJSON(root); pkgJSONPath != "" {
		npm, err := scanNpm(root, pkgJSONPath, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, npm...)
	}
	for _, eco := range ecosystems {
		manifest := findManifest(root, eco.manifest)
		if manifest == "" {
			continue
		}
		refs := eco.parse(manifest)
		if len(refs) == 0 {
			continue
		}
		advisories, err := queryOSV(refs, opts.TimeoutS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "andas: OSV lookup for %s failed (%v); skipping\n", eco.name, err)
			continue
		}
		versionOf := map[string]string{}
		for _, r := range refs {
			versionOf[r.Name] = r.Version
		}
		// Reachability, where this ecosystem supports it: a vulnerable package
		// your source never imports is demoted, exactly as for npm.
		var reachable map[string]bool
		if eco.reach != nil {
			reachable = eco.reach(root, opts.IgnorePaths, refs)
		}
		// Function-level evidence for the reachable vulnerable packages.
		var symbols map[string][]string
		if eco.symbols != nil {
			var wanted []pkgRef
			for _, r := range refs {
				if reachable[r.Name] && len(advisories[r.Name]) > 0 {
					wanted = append(wanted, r)
				}
			}
			symbols = eco.symbols(root, opts.IgnorePaths, wanted)
		}
		for name, advs := range advisories {
			ctx := finding.Context{}
			if eco.reach != nil {
				r := reachable[name]
				ctx.Reachable = &r
				ctx.Note = ecoReachNote(eco.name, r)
				if r {
					ctx.Symbols = symbols[name]
				}
			} else {
				ctx.Note = eco.name + " dependency — reachability analysis not yet available for this ecosystem"
			}
			for _, a := range advs {
				f := finding.Finding{
					Kind:     finding.KindVuln,
					RuleID:   a.ID,
					Title:    vulnTitle(name, a),
					File:     manifest,
					Match:    fmt.Sprintf("%s@%s", name, versionOf[name]),
					Severity: a.Severity,
					Fix:      fmt.Sprintf("Upgrade %s past %s to a patched release; see https://osv.dev/vulnerability/%s", name, versionOf[name], a.ID),
					Context:  ctx,
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// scanNpm runs the JS/TS path: resolve the graph, compute reachability and used
// symbols, and build findings ranked by whether your code actually reaches them.
func scanNpm(root, pkgJSONPath string, opts scanner.Options) ([]finding.Finding, error) {
	projDir := filepath.Dir(pkgJSONPath)
	g, lockKind, err := loadGraph(pkgJSONPath, projDir)
	if err != nil {
		return nil, err
	}
	if lockKind == "package.json (no lockfile)" {
		fmt.Fprintln(os.Stderr, "andas: no lockfile found — scanning direct dependencies only (no transitive graph)")
	}
	if len(g.byName) == 0 {
		return nil, nil
	}

	imports, err := importedPackages(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}
	reached := reachableSet(g, imports)

	refs := make([]pkgRef, 0, len(g.byName))
	for name, p := range g.byName {
		refs = append(refs, pkgRef{Name: name, Version: p.Version, Ecosystem: "npm"})
	}
	advisories, err := queryOSV(refs, opts.TimeoutS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: OSV lookup failed (%v); skipping npm scan\n", err)
		return nil, nil
	}

	wanted := map[string]bool{}
	for name := range advisories {
		if reached[name] {
			wanted[name] = true
		}
	}
	symbols, err := usedSymbols(root, wanted, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}

	var out []finding.Finding
	for name, advs := range advisories {
		p := g.byName[name]
		isReachable := reached[name]
		for _, a := range advs {
			reach := isReachable
			out = append(out, finding.Finding{
				Kind:     finding.KindVuln,
				RuleID:   a.ID,
				Title:    vulnTitle(name, a),
				File:     pkgJSONPath,
				Match:    fmt.Sprintf("%s@%s", name, p.Version),
				Severity: a.Severity,
				Fix:      fmt.Sprintf("Upgrade %s past %s to a patched release; see https://osv.dev/vulnerability/%s", name, p.Version, a.ID),
				Context: finding.Context{
					Reachable: &reach,
					Note:      reachabilityNote(p, isReachable),
					Symbols:   symbols[name],
				},
			})
		}
	}
	return out, nil
}

// hasAnyManifest reports whether the tree holds any dependency manifest at all,
// so offline mode only prints its note when there was something to scan.
func hasAnyManifest(root string) bool {
	if findPackageJSON(root) != "" {
		return true
	}
	for _, eco := range ecosystems {
		if findManifest(root, eco.manifest) != "" {
			return true
		}
	}
	return false
}

// findPackageJSON returns the shallowest package.json under root (skipping
// node_modules), i.e. the app's own manifest, or "" if there is none.
func findPackageJSON(root string) string {
	best := ""
	bestDepth := 1 << 30
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "package.json" {
			depth := strings.Count(path, string(os.PathSeparator))
			if depth < bestDepth {
				bestDepth = depth
				best = path
			}
		}
		return nil
	})
	return best
}

func vulnTitle(name string, a advisory) string {
	summary := a.Summary
	if len(summary) > 80 {
		summary = summary[:77] + "..."
	}
	return fmt.Sprintf("%s — %s", name, summary)
}

func reachabilityNote(p *pkg, reachable bool) string {
	if reachable {
		return "reachable from your app code"
	}
	if p != nil && p.Dev {
		return "dev dependency, not imported by app code — not shipped"
	}
	return "not imported anywhere in your source — transitive/unused"
}

// ecoReachNote is the reachability note for non-npm ecosystems.
func ecoReachNote(eco string, reachable bool) string {
	if reachable {
		return "imported by your " + eco + " code — reachable"
	}
	return "not imported anywhere in your " + eco + " source — unused/transitive"
}
