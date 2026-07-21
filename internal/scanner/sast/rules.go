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
	{"js-sql-concat", "Possible SQL injection (query built by concatenation/template)", finding.SevMedium, "CWE-89", js,
		regexp.MustCompile("(?:\\.query|\\.execute|\\.raw|sequelize\\.query)\\s*\\(\\s*(?:['\"][^'\"]*['\"]\\s*\\+|`[^`]*\\$\\{)"),
		"Use parameterised queries / bound placeholders ($1, ?); never build SQL by string concatenation."},

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

	// --- Broken JWT verification (CWE-347) ---
	{"jwt-none-alg", "JWT verification weakened ('none' algorithm allowed)", finding.SevHigh, "CWE-347",
		merge(js, py),
		regexp.MustCompile(`(?i)algorithms?\s*[:=]\s*\[?\s*['"]none['"]|['"]alg['"]\s*:\s*['"]none['"]`),
		"Pin verification to a specific asymmetric algorithm; never accept 'none'."},
	{"jwt-decode-no-verify", "JWT decoded without verifying its signature", finding.SevHigh, "CWE-347",
		merge(js, py),
		regexp.MustCompile(`jwt\.decode\s*\([^)]*verify\s*[:=]\s*(?:False|false)|jwt\.decode\s*\(\s*[^,)]+\)\s*$`),
		"Verify the signature with jwt.verify / decode(..., verify=True) and the expected key."},

	// --- Insecure cookie flags (CWE-614 / CWE-1004) ---
	{"cookie-insecure", "Cookie set without Secure/HttpOnly", finding.SevMedium, "CWE-614",
		merge(js, py, php),
		regexp.MustCompile(`(?i)httponly\s*[:=]\s*(?:false|0)|secure\s*[:=]\s*false|session\.cookie_httponly\s*=\s*0`),
		"Set HttpOnly and Secure on session/auth cookies; add SameSite."},

	// --- Hardcoded cryptographic key / IV (CWE-321) ---
	{"hardcoded-crypto-key", "Hardcoded cryptographic key or IV", finding.SevHigh, "CWE-321",
		merge(js, py, golang, php, ruby),
		regexp.MustCompile(`(?i)(?:secret|encryption|aes|hmac|signing|jwt)_?key\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{8,}['"]|\bIV\s*[:=]\s*['"][A-Za-z0-9+/=]{8,}['"]`),
		"Load keys from a secrets manager or env var; never embed them in source."},

	// --- CSRF protection disabled (CWE-352) ---
	{"csrf-disabled", "CSRF protection disabled", finding.SevMedium, "CWE-352",
		merge(py, php, ruby),
		regexp.MustCompile(`(?i)@csrf_exempt|csrf\s*[:=]\s*(?:False|false)|WTF_CSRF_ENABLED\s*=\s*False|skip_before_action\s+:verify_authenticity_token`),
		"Keep CSRF protection on for state-changing routes; exempt only APIs with token auth."},

	// --- World-writable file permissions (CWE-732) ---
	{"world-writable", "Overly permissive file mode (world-writable)", finding.SevMedium, "CWE-732",
		merge(py, golang, ruby),
		regexp.MustCompile(`chmod\s*\([^)]*0o?777|os\.chmod\([^)]*0o?666|FileMode\s*\(\s*0o?777`),
		"Grant the least privilege needed; avoid world-writable (0777/0666) modes."},

	// --- LDAP injection (CWE-90) ---
	{"ldap-injection", "Possible LDAP injection (filter built from input)", finding.SevMedium, "CWE-90",
		merge(py, js, php, golang),
		regexp.MustCompile(`(?i)(?:search_s|searchfilter|ldap_search|\.search)\s*\([^)]*(?:\+\s*[A-Za-z_$]|request\.|req\.|\$_(?:GET|POST)|f['"]|#\{)`),
		"Escape LDAP special characters in user input, or use a parameterised filter API."},

	// --- XPath injection (CWE-643) ---
	{"xpath-injection", "Possible XPath injection (query built from input)", finding.SevMedium, "CWE-643",
		merge(py, js, php, ruby, golang),
		regexp.MustCompile(`(?i)(?:xpath|\.evaluate|selectSingleNode|selectNodes|\.compile)\s*\([^)]*(?:\+\s*[A-Za-z_$]|request\.|req\.|\$_(?:GET|POST)|f['"]|#\{)`),
		"Use parameterised XPath or escape input; never concatenate it into the expression."},

	// --- Prototype pollution (CWE-1321) ---
	{"proto-pollution", "Possible prototype pollution (untrusted merge/assign)", finding.SevHigh, "CWE-1321", js,
		regexp.MustCompile(`(?:Object\.assign|_\.merge|_\.mergeWith|_\.defaultsDeep|extend)\s*\([^)]*req\.(?:body|query|params)|\[[^\]]*req\.(?:body|query|params)[^\]]*\]\s*=`),
		"Validate/allowlist keys before merging user data; reject __proto__/constructor keys."},

	// --- Mass assignment (CWE-915) ---
	{"mass-assignment", "Possible mass assignment (whole request bound to a model)", finding.SevMedium, "CWE-915",
		merge(js, py, ruby),
		regexp.MustCompile(`(?i)\.(?:create|update|bulkcreate|insertmany)\s*\(\s*req\.(?:body|query)|new\s+\w+\s*\(\s*req\.body|update_attributes\s*\(\s*params\b|\.new\s*\(\s*params\s*\)|objects\.create\s*\(\s*\*\*request`),
		"Bind only an explicit allowlist of fields (strong params / DTO), not the whole request."},

	// --- Regex from user input / ReDoS (CWE-1333) ---
	{"regex-from-input", "Regex compiled from user input (ReDoS / injection)", finding.SevMedium, "CWE-1333",
		merge(js, py),
		regexp.MustCompile(`new RegExp\s*\(\s*(?:req\.|request\.|[A-Za-z_]\w*\s*[,)])|re\.compile\s*\([^)]*(?:request\.|req\.|\+\s*[A-Za-z_])`),
		"Never build a regex from user input; use a fixed pattern or a safe matcher with a timeout."},

	// --- Node/JS-specific dangerous sinks ---
	{"js-vm-run", "Sandbox escape risk via vm.runIn*/vm.Script", finding.SevHigh, "CWE-95", js,
		regexp.MustCompile(`vm\.(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\s*\(`),
		"Node's vm is not a security sandbox; never run untrusted code through it."},
	{"js-child-spawn-shell", "Command execution with shell enabled", finding.SevHigh, "CWE-78", js,
		regexp.MustCompile(`(?:spawn|execFile)\s*\([^)]*shell\s*:\s*true`),
		"Drop shell:true and pass arguments as an array so input can't break out."},
	{"js-settimeout-string", "Code injection via setTimeout/setInterval with a string", finding.SevHigh, "CWE-95", js,
		regexp.MustCompile(`set(?:Timeout|Interval)\s*\(\s*['"` + "`" + `]`),
		"Pass a function to setTimeout/setInterval, not a string (it's eval in disguise)."},
	{"js-require-dynamic", "Dynamic require()/import() of a variable path", finding.SevMedium, "CWE-95", js,
		regexp.MustCompile(`\brequire\s*\([^)]*(?:req\.|request\.|\+\s*[A-Za-z_])|import\s*\([^)]*(?:req\.|` + "`" + `[^` + "`" + `]*\$\{)`),
		"Load modules from a fixed allowlist; a dynamic path lets an attacker load arbitrary code."},
	{"js-jwt-hardcoded-secret", "JWT signed with a hardcoded secret", finding.SevHigh, "CWE-321", js,
		regexp.MustCompile(`jwt\.sign\s*\([^)]*,\s*['"][^'"]{4,}['"]`),
		"Load the signing secret from a secrets manager or env var, not a string literal."},

	// --- Secret shipped to the browser (CWE-200) ---
	{"frontend-secret", "Secret exposed to the browser (public build-time env var)", finding.SevHigh, "CWE-200", js,
		regexp.MustCompile(`(?:REACT_APP_|NEXT_PUBLIC_|VUE_APP_|VITE_|GATSBY_)[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|APIKEY|API_KEY)`),
		"These env vars are inlined into the client bundle; never put secrets in them — proxy the call through your backend."},
	{"graphql-introspection", "GraphQL introspection/GraphiQL enabled", finding.SevMedium, "CWE-200", merge(js, py),
		regexp.MustCompile(`(?i)introspection\s*:\s*true|graphiql\s*:\s*true|GraphQLView\.as_view\([^)]*graphiql\s*=\s*True`),
		"Disable introspection and GraphiQL in production so the schema isn't handed to attackers."},

	// --- File upload handling (CWE-434) — a surface worth testing ---
	{"file-upload", "File upload handling (test for unrestricted upload)", finding.SevMedium, "CWE-434",
		merge(js, py, php, ruby),
		regexp.MustCompile(`\bmulter\s*\(|req\.files?\b|request\.files\b|\$_FILES\b|move_uploaded_file\s*\(|\.save\s*\([^)]*upload|params\[:file\]|FileField\s*\(`),
		"Validate the file type, size, and destination; store outside the web root with a random name."},

	// --- Weak TLS/SSL protocol version (CWE-326) ---
	// Legacy protocol names use char classes (SSL[v]3, TLS[v]1) so andas doesn't
	// match this very rule when scanning its own source.
	{"weak-tls-version", "Weak SSL/TLS protocol version", finding.SevMedium, "CWE-326",
		merge(py, js, golang),
		regexp.MustCompile(`(?i)SSL[v]3|TLS[v]1(?:\.0|\.1)?['"\s)]|PROTOCOL_SSL[v][23]|MinVersion\s*:\s*tls\.VersionSSL30|secureProtocol\s*:\s*['"](?:SSL[v]3|TLS[v]1)`),
		"Require TLS 1.2 or higher; disable legacy SSL and early TLS."},
}
