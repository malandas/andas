// Package sbom generates a Software Bill of Materials in CycloneDX 1.5 JSON —
// the format most vendors, regulators, and dependency dashboards ingest. andas
// already resolves every dependency across six ecosystems to feed its scanner,
// so emitting an SBOM is just serialising what it already knows, in a standard
// shape teams increasingly must produce.
package sbom

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
)

// Component is one resolved package destined for the SBOM.
type Component struct {
	Name      string
	Version   string
	Ecosystem string // OSV ecosystem: npm, PyPI, Go, ...
}

// purlType maps an OSV ecosystem to its Package-URL type, the CycloneDX
// component identifier. Unknown ecosystems fall back to a "generic" purl.
func purlType(ecosystem string) string {
	switch {
	case ecosystem == "npm":
		return "npm"
	case ecosystem == "PyPI":
		return "pypi"
	case ecosystem == "Go":
		return "golang"
	case ecosystem == "RubyGems":
		return "gem"
	case ecosystem == "crates.io":
		return "cargo"
	case ecosystem == "Packagist":
		return "composer"
	case strings.HasPrefix(ecosystem, "Alpine"):
		return "apk"
	case strings.HasPrefix(ecosystem, "Debian"), strings.HasPrefix(ecosystem, "Ubuntu"):
		return "deb"
	default:
		return "generic"
	}
}

// purl builds a Package URL, e.g. "pkg:npm/lodash@4.17.11".
func purl(c Component) string {
	return "pkg:" + purlType(c.Ecosystem) + "/" + c.Name + "@" + c.Version
}

// Write emits a CycloneDX 1.5 document for the given components. now is an
// RFC3339 timestamp passed in by the caller (andas keeps clock access out of
// library code). Components are de-duplicated and sorted for stable output.
func Write(w io.Writer, components []Component, now string) error {
	seen := map[string]bool{}
	uniq := make([]Component, 0, len(components))
	for _, c := range components {
		key := c.Ecosystem + "|" + c.Name + "|" + c.Version
		if c.Name == "" || seen[key] {
			continue
		}
		seen[key] = true
		uniq = append(uniq, c)
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].Name != uniq[j].Name {
			return uniq[i].Name < uniq[j].Name
		}
		return uniq[i].Version < uniq[j].Version
	})

	type cdxComponent struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	}
	comps := make([]cdxComponent, len(uniq))
	for i, c := range uniq {
		comps[i] = cdxComponent{Type: "library", Name: c.Name, Version: c.Version, Purl: purl(c)}
	}

	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": now,
			"tools": []map[string]any{
				{"vendor": "andas", "name": "andas"},
			},
		},
		"components": comps,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
