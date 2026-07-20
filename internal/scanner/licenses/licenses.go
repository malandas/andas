// Package licenses scans the licenses of installed dependencies and flags ones
// that carry legal obligations — strong copyleft in a proprietary product, or a
// missing license. It reads installed package metadata (node_modules for npm,
// *.dist-info for Python) since that's where real license strings live; if a
// project's dependencies aren't installed, it simply finds nothing rather than
// guess.
package licenses

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/license"
	"github.com/malandas/andas/internal/scanner"
)

type Scanner struct {
	// Proprietary, when set, overrides auto-detection (from .andas.yml `oss`).
	Proprietary *bool
}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "licenses" }

// dep is one installed package with its declared license.
type dep struct {
	name, spdx, path string
}

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	proprietary := s.detectProprietary(root)
	if s.Proprietary != nil {
		proprietary = *s.Proprietary
	}

	deps := collect(root)
	var out []finding.Finding
	seen := map[string]bool{}
	for _, d := range deps {
		risk := license.Classify(d.spdx)
		if risk == license.Permissive {
			continue
		}
		if key := d.name + "|" + d.spdx; seen[key] {
			continue
		} else {
			seen[key] = true
		}
		spdx := d.spdx
		if spdx == "" {
			spdx = "(none)"
		}
		out = append(out, finding.Finding{
			Kind:     finding.KindLicense,
			RuleID:   risk.RuleID(),
			Title:    d.name + " — " + spdx + " (" + risk.String() + ")",
			File:     d.path,
			Match:    d.name + ": " + spdx,
			Severity: risk.Severity(proprietary),
			Fix:      "Confirm this license is compatible with how you distribute your product, or replace the dependency.",
			Context:  finding.Context{Note: risk.Note(spdx, proprietary)},
		})
	}
	return out, nil
}

// collect gathers installed-package licenses from node_modules and dist-info.
func collect(root string) []dep {
	var out []dep
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := d.Name()
		switch {
		case base == "package.json" && strings.Contains(filepath.ToSlash(path), "node_modules/"):
			if name, lic, ok := npmLicense(path); ok {
				out = append(out, dep{name, lic, path})
			}
		case base == "METADATA" && strings.Contains(path, ".dist-info"),
			base == "PKG-INFO" && strings.Contains(path, ".egg-info"):
			if name, lic, ok := pyLicense(path); ok {
				out = append(out, dep{name, lic, path})
			}
		}
		return nil
	})
	return out
}

// npmLicense reads name + license from a node_modules package.json.
func npmLicense(path string) (name, spdx string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	var pj struct {
		Name     string          `json:"name"`
		License  json.RawMessage `json:"license"`
		Licenses json.RawMessage `json:"licenses"`
	}
	if json.Unmarshal(data, &pj) != nil || pj.Name == "" {
		return "", "", false
	}
	return pj.Name, licenseString(pj.License, pj.Licenses), true
}

// licenseString normalises npm's several license shapes to one SPDX-ish string.
func licenseString(license, licenses json.RawMessage) string {
	var s string
	if json.Unmarshal(license, &s) == nil && s != "" {
		return s
	}
	var obj struct{ Type string }
	if json.Unmarshal(license, &obj) == nil && obj.Type != "" {
		return obj.Type
	}
	var arr []struct{ Type string }
	if json.Unmarshal(licenses, &arr) == nil && len(arr) > 0 {
		return arr[0].Type
	}
	return ""
}

// pyLicense reads a package's license from a dist-info METADATA file.
func pyLicense(path string) (name, spdx string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "Name: "):
			name = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "License-Expression: "):
			spdx = strings.TrimSpace(line[len("License-Expression: "):])
		case spdx == "" && strings.HasPrefix(line, "License: "):
			spdx = strings.TrimSpace(line[len("License: "):])
		case spdx == "" && strings.HasPrefix(line, "Classifier: License :: "):
			spdx = strings.TrimSpace(line[strings.LastIndex(line, "::")+2:])
		}
	}
	if name == "" {
		return "", "", false
	}
	return name, spdx, true
}

// detectProprietary guesses whether the project is closed-source: a "private"
// or "UNLICENSED" package.json means proprietary; a recognised OSS license means
// not. Absent any signal it assumes proprietary, the more useful default.
func (s *Scanner) detectProprietary(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return true
	}
	var pj struct {
		Private bool            `json:"private"`
		License json.RawMessage `json:"license"`
	}
	if json.Unmarshal(data, &pj) != nil {
		return true
	}
	lic := licenseString(pj.License, nil)
	if pj.Private || strings.EqualFold(lic, "UNLICENSED") || lic == "" {
		return true
	}
	return license.Classify(lic) == license.Unknown
}
