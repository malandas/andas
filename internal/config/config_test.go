package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	c := parse("fail-on: critical\ndisable:\n  - rule-a\n  - rule-b\nignore:\n  - testdata\n")
	if c.FailOn != "critical" {
		t.Errorf("fail-on = %q", c.FailOn)
	}
	if !c.Disabled("rule-a") || !c.Disabled("rule-b") {
		t.Error("rules not disabled")
	}
	if c.Disabled("rule-c") {
		t.Error("rule-c should not be disabled")
	}
	if len(c.Ignore) != 1 || c.Ignore[0] != "testdata" {
		t.Errorf("ignore = %v", c.Ignore)
	}
}

func TestParseInlineList(t *testing.T) {
	c := parse(`disable: [a, "b", c]`)
	if !c.Disabled("a") || !c.Disabled("b") || !c.Disabled("c") {
		t.Errorf("inline list not parsed: %v", c.Disable)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil || len(c.Disable) != 0 {
		t.Errorf("missing config should be empty, got %v %v", c, err)
	}
}

func TestLoadReal(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".andas.yml"), []byte("disable:\n  - x\n"), 0o644)
	c, _ := Load(dir)
	if !c.Disabled("x") {
		t.Error("loaded config did not disable x")
	}
}
