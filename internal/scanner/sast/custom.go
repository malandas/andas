package sast

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// Custom rules let a team or a pentester extend andas with their own SAST
// patterns — no rebuild, no plugin. Drop a `.andas-rules.yml` in the scan root:
//
//	- id: my-rule
//	  title: Dangerous internal helper
//	  severity: high
//	  cwe: CWE-000
//	  langs: [js, py]
//	  pattern: 'dangerousCall\('
//	  fix: Use the safe wrapper instead.
//
// This is what turns andas from a fixed tool into a platform.

var langExts = map[string]map[string]bool{
	"js": js, "ts": js, "javascript": js, "typescript": js,
	"py": py, "python": py,
	"rb": ruby, "ruby": ruby,
	"php": php,
	"go": golang, "golang": golang,
}

// loadCustomRules reads and compiles user rules from `.andas-rules.yml`. Invalid
// entries (bad regex, missing fields) are skipped silently so one typo can't
// break a scan.
func loadCustomRules(root string) []rule {
	data, err := os.ReadFile(filepath.Join(root, ".andas-rules.yml"))
	if err != nil {
		return nil
	}
	var out []rule
	var cur map[string]string
	flush := func() {
		if cur == nil {
			return
		}
		defer func() { cur = nil }()
		pat, err := regexp.Compile(cur["pattern"])
		if cur["id"] == "" || cur["pattern"] == "" || err != nil {
			return
		}
		exts := map[string]bool{}
		for _, l := range splitList(cur["langs"]) {
			for e := range langExts[strings.ToLower(strings.TrimSpace(l))] {
				exts[e] = true
			}
		}
		if len(exts) == 0 {
			// no langs specified → apply to all supported source files
			for _, m := range []map[string]bool{js, py, ruby, php, golang} {
				for e := range m {
					exts[e] = true
				}
			}
		}
		title := cur["title"]
		if title == "" {
			title = cur["id"]
		}
		out = append(out, rule{
			id: "custom:" + cur["id"], title: title, sev: parseSev(cur["severity"]),
			cwe: cur["cwe"], exts: exts, pat: pat, fix: cur["fix"],
		})
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if k, v, ok := listItemKV(line); ok { // "- id: x" starts a new rule
			flush()
			cur = map[string]string{}
			if k != "" {
				cur[k] = v
			}
			continue
		}
		if cur != nil {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				cur[strings.TrimSpace(line[:i])] = unquote(strings.TrimSpace(line[i+1:]))
			}
		}
	}
	flush()
	return out
}

// listItemKV parses "- id: value" → ("id","value",true); "- foo" → ("","",true).
func listItemKV(line string) (key, val string, ok bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "-") {
		return "", "", false
	}
	t = strings.TrimSpace(t[1:])
	if i := strings.IndexByte(t, ':'); i >= 0 {
		return strings.TrimSpace(t[:i]), unquote(strings.TrimSpace(t[i+1:])), true
	}
	return "", "", true
}

func splitList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func parseSev(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SevCritical
	case "high":
		return finding.SevHigh
	case "low":
		return finding.SevLow
	case "info":
		return finding.SevInfo
	default:
		return finding.SevMedium
	}
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
