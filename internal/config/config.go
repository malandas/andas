// Package config loads an optional .andas.yml from the scan root so a team can
// tune andas without touching flags: silence rules that don't apply, add ignore
// globs, and set the default fail-on level. Parsed with a tiny hand-rolled
// reader (a flat subset of YAML) to keep andas dependency-free.
package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config is the tunable policy for a scan. A zero Config means "no config file";
// every field is optional and additive to command-line flags.
type Config struct {
	Disable []string // rule IDs to skip entirely
	Ignore  []string // extra ignore globs, merged with .andasignore
	FailOn  string   // default --fail-on when the flag is left at its default
}

// Disabled reports whether a rule id is switched off.
func (c *Config) Disabled(ruleID string) bool {
	for _, d := range c.Disable {
		if d == ruleID {
			return true
		}
	}
	return false
}

// Load reads .andas.yml from root. A missing file yields an empty Config and no
// error — config is always optional.
func Load(root string) (*Config, error) {
	path := filepath.Join(root, ".andas.yml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parse(string(data)), nil
}

// parse reads the flat subset we support:
//
//	fail-on: high
//	disable:
//	  - rule-id
//	  - other-rule
//	ignore:
//	  - testdata
//	  - "*.min.js"
func parse(text string) *Config {
	c := &Config{}
	current := "" // which list-key we're collecting items under
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// A list item: "  - value"
		if item, ok := listItem(line); ok {
			switch current {
			case "disable":
				c.Disable = append(c.Disable, item)
			case "ignore":
				c.Ignore = append(c.Ignore, item)
			}
			continue
		}
		// A top-level "key: value" (or "key:" opening a list).
		key, val := splitKey(line)
		current = key
		switch key {
		case "fail-on":
			if val != "" {
				c.FailOn = val
			}
		case "disable", "ignore":
			// inline form "disable: [a, b]" is also accepted
			for _, it := range inlineList(val) {
				if key == "disable" {
					c.Disable = append(c.Disable, it)
				} else {
					c.Ignore = append(c.Ignore, it)
				}
			}
		}
	}
	return c
}

func listItem(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "- ") && t != "-" {
		return "", false
	}
	return unquote(strings.TrimSpace(strings.TrimPrefix(t, "-"))), true
}

func splitKey(line string) (key, val string) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return strings.TrimSpace(line), ""
	}
	return strings.TrimSpace(line[:i]), unquote(strings.TrimSpace(line[i+1:]))
}

// inlineList parses "[a, b, c]"; returns nil for anything else.
func inlineList(val string) []string {
	if !strings.HasPrefix(val, "[") || !strings.HasSuffix(val, "]") {
		return nil
	}
	var out []string
	for _, p := range strings.Split(val[1:len(val)-1], ",") {
		if p = unquote(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
