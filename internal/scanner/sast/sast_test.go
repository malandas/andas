package sast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
)

func scanSrc(t *testing.T, name, src string) []finding.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := New().Scan(dir, scanner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func hasRule(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].RuleID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestSAST_DetectsDangerousPatterns(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.py", "os.system('ping ' + x)", "py-os-command"},
		{"a.py", "eval(userstr)", "py-eval-exec"},
		{"a.py", "pickle.loads(data)", "py-pickle"},
		{"a.js", "child_process.exec('ls ' + d)", "js-child-process"},
		{"a.js", "el.innerHTML = x", "js-xss-sink"},
		{"a.php", "echo $_GET['n'];", "php-echo-input"},
		{"a.php", "unserialize($_POST['d']);", "php-unserialize"},
		// Assembled from split literals so andas doesn't flag its own test file.
		{"a.go", "exec.Command(" + `"sh", "-c", cmd)`, "go-shell"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_UserInputRaisesConfidence(t *testing.T) {
	// Same sink; the one fed user input must be flagged as such.
	tainted := scanSrc(t, "a.py", "os.system('x ' + request.args.get('c'))")
	if f := hasRule(tainted, "py-os-command"); f == nil || !f.Context.UserInput {
		t.Error("user-controlled input should be detected on the tainted line")
	}
	clean := scanSrc(t, "b.py", "os.system('ls -la')")
	if f := hasRule(clean, "py-os-command"); f == nil || f.Context.UserInput {
		t.Error("a constant-arg command must not be flagged as user-controlled")
	}
}

func TestSAST_NoFalsePositiveOnSafeVariants(t *testing.T) {
	// yaml.safe_load and parameterized queries must NOT trigger.
	if f := scanSrc(t, "a.py", "yaml.safe_load(open('c'))"); len(f) != 0 {
		t.Errorf("yaml.safe_load should be clean, got %v", f)
	}
	if f := scanSrc(t, "a.py", "cur.execute('SELECT * FROM t WHERE id=%s', (id,))"); len(f) != 0 {
		t.Errorf("parameterized query should be clean, got %v", f)
	}
}

func TestSAST_RespectsExtensions(t *testing.T) {
	// A PHP pattern must not fire inside a .py file.
	if f := scanSrc(t, "a.py", "echo $_GET['x'];"); hasRule(f, "php-echo-input") != nil {
		t.Error("php rule fired on a .py file")
	}
}

func TestSAST_NewVulnClasses(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.py", "open('/d/' + request.args.get('f'))", "py-path-traversal"},
		{"a.py", "requests.get(request.args.get('u'))", "py-ssrf"},
		{"a.py", "hashlib.md5(pw)", "weak-hash"},
		{"a.py", "render_template_string(request.args.get('t'))", "py-ssti"},
		{"a.py", "etree.parse(f)", "py-xxe"},
		{"a.js", "const t = Math.random()", "insecure-random"},
		{"a.js", "axios(req.query.target)", "js-ssrf"},
		{"a.js", "res.redirect(req.query.next)", "open-redirect"},
		{"a.js", "db.find(req.body)", "nosql-where"},
		{"a.php", "include($_GET['p']);", "php-path-traversal"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_NewClassesNoFalsePositive(t *testing.T) {
	// Safe idioms must stay clean.
	if f := scanSrc(t, "a.py", "hashlib.sha256(x)"); len(f) != 0 {
		t.Errorf("sha256 should be clean, got %v", f)
	}
	if f := scanSrc(t, "a.py", "open('config.txt')"); len(f) != 0 {
		t.Errorf("constant open() should be clean, got %v", f)
	}
}
