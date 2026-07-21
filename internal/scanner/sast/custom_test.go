package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCustomRules(t *testing.T) {
	dir := t.TempDir()
	yml := "- id: my-rule\n  title: My Rule\n  severity: high\n  cwe: CWE-000\n  langs: [js]\n  pattern: 'dangerZone\\('\n  fix: stop\n"
	os.WriteFile(filepath.Join(dir, ".andas-rules.yml"), []byte(yml), 0o644)
	rs := loadCustomRules(dir)
	if len(rs) != 1 {
		t.Fatalf("want 1 custom rule, got %d", len(rs))
	}
	r := rs[0]
	if r.id != "custom:my-rule" || r.cwe != "CWE-000" || !r.exts[".js"] || r.exts[".py"] {
		t.Errorf("custom rule parsed wrong: %+v", r)
	}
	if !r.pat.MatchString("dangerZone(x)") {
		t.Error("custom pattern did not compile/match")
	}
	// a bad regex must be skipped, not crash
	os.WriteFile(filepath.Join(dir, ".andas-rules.yml"), []byte("- id: bad\n  pattern: '([unclosed'\n"), 0o644)
	if len(loadCustomRules(dir)) != 0 {
		t.Error("invalid regex rule should be skipped")
	}
}

func TestInterproceduralTaint(t *testing.T) {
	lines := []string{
		"def run_cmd(userval):",
		"    os.system(userval)", // sink uses the param
		"def handler(request):",
		"    run_cmd(request.args.get('h'))", // user input into run_cmd
	}
	got := taintedLines(lines, ".py")
	if !got[1] {
		t.Error("the sink in run_cmd should be tainted via the inter-procedural hop")
	}
}
