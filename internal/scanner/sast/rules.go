// Package sast statically scans the user's *own* source for dangerous code
// patterns — code injection, command execution, unsafe deserialization, and so
// on. The rules are deliberately tight and high-signal: andas would rather miss
// a subtle bug than bury a real one under false positives. Detection is
// pattern-based (not full taint analysis), so each finding notes whether
// user-controlled input appears on the same line — the strongest cheap signal
// that a dangerous sink is actually reachable by an attacker.
package sast

import (
	"regexp"

	"github.com/malandas/andas/internal/finding"
)

type rule struct {
	id    string
	title string
	sev   finding.Severity
	cwe   string
	exts  map[string]bool
	pat   *regexp.Regexp
	fix   string
}

func exts(e ...string) map[string]bool {
	m := make(map[string]bool, len(e))
	for _, x := range e {
		m[x] = true
	}
	return m
}

var (
	js     = exts(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
	py     = exts(".py")
	ruby   = exts(".rb")
	php    = exts(".php")
	golang = exts(".go")
)

func merge(ms ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		for k := range m {
			out[k] = true
		}
	}
	return out
}

var rules = []rule{
	// --- Code injection (CWE-95) ---
	{"js-eval", "Code injection via eval()", finding.SevHigh, "CWE-95", js,
		regexp.MustCompile(`\beval\s*\(`), "Never eval() dynamic input; use JSON.parse for data or a safe dispatch table."},
	{"js-new-function", "Code injection via new Function()", finding.SevHigh, "CWE-95", js,
		regexp.MustCompile(`\bnew\s+Function\s*\(`), "Avoid the Function constructor with dynamic strings."},
	{"py-eval-exec", "Code injection via eval()/exec()", finding.SevHigh, "CWE-95", py,
		regexp.MustCompile(`\b(?:eval|exec)\s*\(`), "Never eval()/exec() dynamic input; use ast.literal_eval for data."},
	{"ruby-eval", "Code injection via eval", finding.SevHigh, "CWE-95", ruby,
		regexp.MustCompile(`\b(?:eval|instance_eval|class_eval)\s*[\s(]`), "Avoid eval on dynamic input."},
	{"php-eval", "Code injection via eval()", finding.SevHigh, "CWE-95", php,
		regexp.MustCompile(`\beval\s*\(`), "Remove eval(); restructure to avoid executing dynamic code."},

	// --- OS command injection (CWE-78) ---
	{"py-os-command", "OS command execution", finding.SevHigh, "CWE-78", py,
		regexp.MustCompile(`\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True`),
		"Pass an argument list without shell=True; never interpolate input into a shell string."},
	{"js-child-process", "OS command execution via child_process.exec", finding.SevHigh, "CWE-78", js,
		regexp.MustCompile(`child_process\.exec(?:Sync)?\s*\(|\bexec(?:Sync)?\s*\(\s*['"\x60]`),
		"Use execFile/spawn with an argument array instead of exec with a shell string."},
	{"ruby-command", "OS command execution", finding.SevHigh, "CWE-78", ruby,
		regexp.MustCompile("\\bsystem\\s*\\(|`[^`]*#\\{|%x\\(|Open3\\."),
		"Pass command arguments as an array; never interpolate input into a shell command."},
	{"php-command", "OS command execution", finding.SevHigh, "CWE-78", php,
		regexp.MustCompile(`\b(?:shell_exec|passthru|proc_open|popen)\s*\(|\b(?:system|exec)\s*\(`),
		"Avoid shelling out with user input; use escapeshellarg or a safe library."},
	{"go-shell", "OS command execution via a shell", finding.SevHigh, "CWE-78", golang,
		regexp.MustCompile(`exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"`),
		"Invoke the program directly with args rather than sh -c with an interpolated string."},

	// --- Unsafe deserialization (CWE-502) ---
	// yaml.load(/YAML.load( are unsafe; the safe_load variants don't match this
	// pattern (RE2 has no lookahead, and none is needed — "yaml.load" is not a
	// substring of "yaml.safe_load").
	{"py-pickle", "Unsafe deserialization", finding.SevHigh, "CWE-502", py,
		regexp.MustCompile(`\bpickle\.loads?\s*\(|\byaml\.load(?:_all)?\s*\(`),
		"Use safe formats (json) or yaml.safe_load; never unpickle untrusted data."},
	{"ruby-marshal", "Unsafe deserialization", finding.SevHigh, "CWE-502", ruby,
		regexp.MustCompile(`Marshal\.load\s*\(|YAML\.load\s*\(`),
		"Use YAML.safe_load / JSON; never Marshal.load untrusted data."},
	{"php-unserialize", "Unsafe deserialization", finding.SevHigh, "CWE-502", php,
		regexp.MustCompile(`\bunserialize\s*\(`), "Use json_decode; never unserialize untrusted input."},

	// --- Disabled TLS verification (CWE-295) ---
	{"tls-disabled", "TLS certificate verification disabled", finding.SevMedium, "CWE-295",
		merge(py, js, golang),
		regexp.MustCompile(`verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true`),
		"Never disable certificate verification in production; fix the trust store instead."},

	// --- Cross-site scripting (CWE-79) ---
	{"js-xss-sink", "Possible XSS via raw HTML sink", finding.SevMedium, "CWE-79", js,
		regexp.MustCompile(`dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(`),
		"Render text, not HTML; sanitize with a vetted library if raw HTML is unavoidable."},
	{"php-echo-input", "Reflected XSS: user input echoed directly", finding.SevHigh, "CWE-79", php,
		regexp.MustCompile(`echo\s+\$_(?:GET|POST|REQUEST|COOKIE)`),
		"Escape output with htmlspecialchars() before echoing user input."},

	// --- SQL injection (CWE-89) — moderate confidence, string building in a query ---
	{"py-sql-fstring", "Possible SQL injection (f-string in query)", finding.SevMedium, "CWE-89", py,
		regexp.MustCompile(`(?:execute|executemany)\s*\(\s*f['"]`),
		"Use parameterized queries (execute(sql, params)); never format values into SQL."},
	{"ruby-sql-interp", "Possible SQL injection (interpolation in query)", finding.SevMedium, "CWE-89", ruby,
		regexp.MustCompile(`\.(?:where|find_by_sql|execute)\s*\(\s*["'][^"']*#\{`),
		"Use parameter placeholders (where('x = ?', v)); never interpolate into SQL."},
	{"php-sql-var", "Possible SQL injection (variable in query)", finding.SevMedium, "CWE-89", php,
		regexp.MustCompile(`(?:mysqli_query|->query|->exec)\s*\(\s*["'][^"']*\$`),
		"Use prepared statements with bound parameters instead of interpolating variables."},
}
