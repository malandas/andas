package deps

import (
	"regexp"
	"strings"
)

// Function-level evidence for Ruby, Rust, and PHP — completing the matrix.
// Evidence only, as with every other language: it says which parts of a
// vulnerable package your code touches, and never downgrades on that alone.

// --- Ruby: Gem -> top-level constant, then Constant::x / Constant.x ---

var rubyConstAliases = map[string]string{
	"rails": "Rails", "pg": "PG", "json": "JSON", "yaml": "YAML",
	"aws-sdk": "Aws", "rspec": "RSpec", "oj": "Oj",
}

func rubyConstant(gem string) string {
	if c, ok := rubyConstAliases[strings.ToLower(gem)]; ok {
		return c
	}
	parts := strings.FieldsFunc(gem, func(r rune) bool { return r == '-' || r == '_' })
	var b strings.Builder
	for _, p := range parts {
		if p != "" {
			b.WriteString(strings.ToUpper(p[:1]) + p[1:])
		}
	}
	return b.String()
}

func rubySymbols(root string, ignore []string, wanted []pkgRef) map[string][]string {
	acc := map[string]map[string]bool{}
	for _, r := range wanted {
		con := rubyConstant(r.Name)
		if con == "" {
			continue
		}
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(con) + `(?:::|\.)([A-Za-z_]\w*)`)
		for _, f := range langFiles(root, ignore, ".rb") {
			for _, m := range re.FindAllStringSubmatch(strings.Join(f.Lines, "\n"), -1) {
				if acc[r.Name] == nil {
					acc[r.Name] = map[string]bool{}
				}
				acc[r.Name][m[1]] = true
			}
		}
	}
	return finalizeSyms(acc)
}

// --- Rust: crate_name::Item ---

func rustSymbols(root string, ignore []string, wanted []pkgRef) map[string][]string {
	acc := map[string]map[string]bool{}
	for _, r := range wanted {
		crate := strings.ReplaceAll(r.Name, "-", "_")
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(crate) + `::([A-Za-z_]\w*)`)
		for _, f := range langFiles(root, ignore, ".rs") {
			for _, m := range re.FindAllStringSubmatch(strings.Join(f.Lines, "\n"), -1) {
				if acc[r.Name] == nil {
					acc[r.Name] = map[string]bool{}
				}
				acc[r.Name][m[1]] = true
			}
		}
	}
	return finalizeSyms(acc)
}

// --- PHP: use Ns\...\Class -> Class, mapped to package via composer.lock ---

var rePhpUseFull = regexp.MustCompile(`\buse\s+\\?([A-Za-z_][A-Za-z0-9_\\]*)`)

func phpSymbols(root string, ignore []string, wanted []pkgRef) map[string][]string {
	nsToPkg := phpNamespaceMap(findManifest(root, "composer.lock"))
	want := map[string]bool{}
	for _, r := range wanted {
		want[r.Name] = true
	}
	acc := map[string]map[string]bool{}
	for _, f := range langFiles(root, ignore, ".php") {
		for _, line := range f.Lines {
			m := rePhpUseFull.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			full := m[1]
			pkg, ok := nsToPkg[rootNamespace(full)]
			if !ok || !want[pkg] {
				continue
			}
			class := full
			if i := strings.LastIndex(full, `\`); i >= 0 {
				class = full[i+1:]
			}
			if acc[pkg] == nil {
				acc[pkg] = map[string]bool{}
			}
			acc[pkg][class] = true
		}
	}
	return finalizeSyms(acc)
}
