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
	pkgJSONPath := findPackageJSON(root)
	if pkgJSONPath == "" {
		return nil, nil // not a JS/TS project; nothing to do
	}
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

	// Reachability is local and always runs — it's the context that matters
	// even when we can reuse cached vuln data later.
	imports, err := importedPackages(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}
	reached := reachableSet(g, imports)

	if opts.Offline {
		fmt.Fprintln(os.Stderr, "andas: offline mode — skipping OSV vulnerability lookup")
		return nil, nil
	}

	advisories, err := queryOSV(g, opts.TimeoutS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: OSV lookup failed (%v); skipping dependency scan\n", err)
		return nil, nil
	}

	// For the vulnerable *reachable* packages, gather which of their exports the
	// app actually uses — evidence for triage attached to each finding.
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
			note := reachabilityNote(p, isReachable)
			reach := isReachable
			f := finding.Finding{
				Kind:     finding.KindVuln,
				RuleID:   a.ID,
				Title:    vulnTitle(name, a),
				File:     pkgJSONPath,
				Match:    fmt.Sprintf("%s@%s", name, p.Version),
				Severity: a.Severity,
				Fix:      fmt.Sprintf("Upgrade %s past %s to a patched release; see https://osv.dev/vulnerability/%s", name, p.Version, a.ID),
				Context: finding.Context{
					Reachable: &reach,
					Note:      note,
					Symbols:   symbols[name],
				},
			}
			out = append(out, f)
		}
	}
	return out, nil
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
