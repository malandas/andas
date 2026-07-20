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

	// --- Path traversal (CWE-22) — reading a file from a variable path ---
	{"py-path-traversal", "Possible path traversal (file opened from a variable)", finding.SevMedium, "CWE-22", py,
		regexp.MustCompile(`\b(?:open|send_file)\s*\([^)]*(?:request\.|\+)|os\.path\.join\s*\([^)]*request\.`),
		"Resolve and validate the path against a fixed base dir; reject '..' components."},
	{"js-path-traversal", "Possible path traversal (file read from a variable)", finding.SevMedium, "CWE-22", js,
		regexp.MustCompile(`(?:readFile|readFileSync|sendFile|createReadStream)\s*\([^)]*(?:req\.|\+\s*[A-Za-z_])`),
		"Normalise the path and confirm it stays within an allowed root before reading."},
	{"php-path-traversal", "Possible path traversal (file included/opened from input)", finding.SevHigh, "CWE-22", php,
		regexp.MustCompile(`\b(?:include|require|include_once|require_once|fopen|file_get_contents)\s*\(?\s*\$_(?:GET|POST|REQUEST)`),
		"Never build a file path from user input; use a fixed allowlist of files."},

	// --- Server-Side Request Forgery (CWE-918) — fetching a user-controlled URL ---
	{"py-ssrf", "Possible SSRF (request to a variable URL)", finding.SevMedium, "CWE-918", py,
		regexp.MustCompile(`requests\.(?:get|post|put|delete|head)\s*\(\s*(?:[A-Za-z_]\w*\s*\+|f['"]|request\.)|urllib\.request\.urlopen\s*\(`),
		"Validate the URL against an allowlist of hosts; block internal/link-local ranges."},
	{"js-ssrf", "Possible SSRF (request to a variable URL)", finding.SevMedium, "CWE-918", js,
		regexp.MustCompile(`(?:axios|fetch|http\.get|https\.get|request)\s*\(\s*(?:req\.|[A-Za-z_]\w*\s*\+|` + "`" + `[^` + "`" + `]*\$\{)`),
		"Allowlist destination hosts and reject requests to internal addresses."},

	// --- Weak cryptography (CWE-327 / CWE-328 / CWE-338) ---
	{"weak-hash", "Weak hashing algorithm (MD5/SHA1)", finding.SevMedium, "CWE-328",
		merge(py, js, golang, php, ruby),
		regexp.MustCompile(`(?i)(?:hashlib\.(?:md5|sha1)|createHash\s*\(\s*['"](?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)|md5\s*\(|Digest::(?:MD5|SHA1))`),
		"Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords."},
	{"insecure-random", "Insecure randomness used where security matters", finding.SevMedium, "CWE-338",
		merge(py, js, golang),
		regexp.MustCompile(`Math\.random\s*\(\)|random\.random\s*\(\)|math[/]rand`),
		"Use a CSPRNG (crypto.randomBytes, secrets, crypto/rand) for tokens, keys, or IDs."},

	// --- XXE: XML parsing with external entities (CWE-611) ---
	{"py-xxe", "XML parsed with an entity-unsafe parser", finding.SevMedium, "CWE-611", py,
		regexp.MustCompile(`etree\.(?:parse|fromstring)\s*\(|xml\.dom\.minidom\.parse|xml\.sax\.`),
		"Use defusedxml, or disable external entities/DTDs on the parser."},
	{"php-xxe", "XML loaded with external entities allowed", finding.SevMedium, "CWE-611", php,
		regexp.MustCompile(`LIBXML_NOENT|simplexml_load_(?:string|file)\s*\(`),
		"Do not enable LIBXML_NOENT; keep libxml_disable_entity_loader in effect."},

	// --- Server-Side Template Injection (CWE-1336) ---
	{"py-ssti", "Possible template injection (template built from input)", finding.SevHigh, "CWE-1336", py,
		regexp.MustCompile(`(?:render_template_string|Template)\s*\(\s*(?:[A-Za-z_]\w*\s*\+|f['"]|request\.)`),
		"Render a fixed template with variables as data; never build the template string from input."},

	// --- Open redirect (CWE-601) ---
	{"open-redirect", "Possible open redirect (redirect to a variable URL)", finding.SevMedium, "CWE-601",
		merge(py, js, php),
		regexp.MustCompile(`redirect\s*\(\s*(?:request\.|req\.|\$_(?:GET|POST|REQUEST))|res\.redirect\s*\(\s*req\.`),
		"Redirect only to a fixed allowlist of paths; never to a raw user-supplied URL."},

	// --- NoSQL injection (CWE-943) ---
	{"nosql-where", "Possible NoSQL injection ($where / user object in query)", finding.SevMedium, "CWE-943",
		merge(js, py),
		regexp.MustCompile(`\$where\s*[:=]|\.find\s*\(\s*(?:req\.body|req\.query|request\.)`),
		"Never pass raw request objects into a query; validate and cast fields explicitly."},
}
