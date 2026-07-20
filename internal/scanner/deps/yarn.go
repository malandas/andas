package deps

import (
	"strings"
)

// parseYarnLock parses a yarn.lock into resolved packages, handling both the
// classic v1 format and Yarn Berry (v2+). Both share the same indentation-based
// block structure: top-level blocks are headed by one or more comma-separated
// descriptors ending in ":", and each carries a resolved `version` and an
// optional `dependencies:` sub-block. They differ only in punctuation — classic
// uses `version "x"` / `dep "range"`, Berry uses `version: x` / `dep: "range"` —
// which the field parsers below absorb. yarn.lock carries no dev/prod flag, so
// the caller derives that from package.json; returned pkgs have Dev left false.
func parseYarnLock(data []byte) map[string]*pkg {
	out := map[string]*pkg{}
	lines := strings.Split(string(data), "\n")

	var names []string // package names the current block resolves
	var cur *pkg
	inDeps := false

	flush := func() {
		if cur == nil || cur.Version == "" {
			return
		}
		for _, n := range names {
			if n == "__metadata" { // Berry's header block, not a package
				continue
			}
			out[n] = &pkg{Name: n, Version: cur.Version, Deps: cur.Deps}
		}
	}

	for _, line := range lines {
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// Top-level header (column 0) starts a new block.
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			names = names[:0]
			seen := map[string]bool{}
			for _, desc := range strings.Split(header, ", ") {
				if n := descriptorName(desc); n != "" && !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
			}
			cur = &pkg{}
			inDeps = false
			continue
		}

		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		switch {
		case strings.HasPrefix(trimmed, "version"):
			// classic: version "4.17.11"  ·  Berry: version: 4.17.11
			cur.Version = strings.Trim(trimmed[len("version"):], "\": ")
			inDeps = false
		case trimmed == "dependencies:" || trimmed == "optionalDependencies:":
			inDeps = true
		case inDeps && indent >= 4:
			if dep := firstToken(trimmed); dep != "" {
				cur.Deps = append(cur.Deps, dep)
			}
		default:
			inDeps = false // resolved/integrity/etc. — end of any deps block
		}
	}
	flush()
	return out
}

// descriptorName extracts the package name from a yarn descriptor such as
// `lodash@^4.17.11`, `"@scope/name@^1.0.0"`, or `foo@npm:^1.0.0`.
func descriptorName(desc string) string {
	desc = strings.TrimSpace(desc)
	desc = strings.Trim(desc, "\"")
	// The version separator is the LAST '@' (a leading '@' belongs to a scope).
	at := strings.LastIndex(desc, "@")
	if at <= 0 {
		return desc
	}
	return desc[:at]
}

// firstToken returns the dependency name from a yarn dependency line, handling
// classic `debug "^2.6.9"` and `"@babel/core" "^7.0.0"` as well as Berry's
// colon form `debug: "npm:^2.6.9"` and `"@babel/core": "npm:^7.0.0"`.
func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "\"") {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end]
		}
	}
	tok := s
	if i := strings.IndexByte(tok, ' '); i >= 0 {
		tok = tok[:i]
	}
	return strings.TrimSuffix(tok, ":") // Berry: `debug:` -> `debug`
}
