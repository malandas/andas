package sast

import (
	"os"
	"path/filepath"
	"strings"
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
		{"a.py", "hashlib." + "md5(pw)", "weak-hash"},
		{"a.py", "render_template_string(request.args.get('t'))", "py-ssti"},
		{"a.py", "etree.parse(f)", "py-xxe"},
		{"a.js", "const t = Math." + "random()", "insecure-random"},
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

func TestSAST_V14Classes(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.py", "jwt.decode(token, verify=False)", "jwt-decode-no-verify"},
		{"a.py", "algorithms=['none']", "jwt-none-alg"},
		{"a.js", "res.cookie('s', v, { httpOnly: false })", "cookie-insecure"},
		{"a.py", "signing_key = " + "\"" + "s3cr3t_hardcoded_val" + "\"", "hardcoded-crypto-key"},
		{"a.py", "@csrf_exempt", "csrf-disabled"},
		{"a.py", "os.chmod(p, 0o777)", "world-writable"},
		{"a.js", "const o = { secureProtocol: 'TLSv1_method' }", "weak-tls-version"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_V15Classes(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.js", "const re = new RegExp(req.query.p)", "regex-from-input"},
		{"a.js", "Object.assign(target, req.body)", "proto-pollution"},
		{"a.js", "User.create(req.body)", "mass-assignment"},
		{"a.js", "doc.evaluate(req.query.xp, node)", "xpath-injection"},
		{"a.py", "ldap.search_s(b, s, \"(uid=\" + request.args.get('u'))", "ldap-injection"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_IgnoresComments(t *testing.T) {
	// Dangerous patterns inside comments must NOT fire (false-positive reduction).
	if f := scanSrc(t, "a.py", "# eval(user_input) is dangerous"); len(f) != 0 {
		t.Errorf("commented eval should be clean, got %v", f)
	}
	if f := scanSrc(t, "a.js", "// child_process.exec(cmd) removed"); len(f) != 0 {
		t.Errorf("commented exec should be clean, got %v", f)
	}
	// ...but real code on a non-comment line still fires.
	if hasRule(scanSrc(t, "a.py", "eval(x)"), "py-eval-exec") == nil {
		t.Error("real eval() should still be detected")
	}
}

func TestSAST_SkipsMinifiedLines(t *testing.T) {
	long := "var x=eval(" + strings.Repeat("a", 1100) + ")"
	if f := scanSrc(t, "a.js", long); len(f) != 0 {
		t.Errorf("minified/very-long line should be skipped, got %v", f)
	}
}

func TestSAST_JSRules(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.js", "db.query(\"SELECT * FROM u WHERE id=\" + req.query.id)", "js-sql-concat"},
		{"a.js", "vm.runInNewContext(code)", "js-vm-run"},
		{"a.js", "spawn(cmd, args, { shell: true })", "js-child-spawn-shell"},
		{"a.js", "setTimeout(\"go()\", 10)", "js-settimeout-string"},
		{"a.js", "require(\"./\" + req.query.m)", "js-require-dynamic"},
		{"a.js", "jwt.sign(p, \"hardcoded_key_x\")", "js-jwt-hardcoded-secret"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_FileUpload(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.js", "const f = req.files.doc"},
		{"a.php", "move_uploaded_file($_FILES['f']['tmp_name'], $p);"},
	} {
		if hasRule(scanSrc(t, c.name, c.src), "file-upload") == nil {
			t.Errorf("%s: file-upload not detected on %q", c.name, c.src)
		}
	}
}

func TestSAST_FrontendAndGraphQL(t *testing.T) {
	if hasRule(scanSrc(t, "a.js", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY"), "frontend-secret") == nil {
		t.Error("frontend secret (NEXT_PUBLIC_*_SECRET) not detected")
	}
	if hasRule(scanSrc(t, "a.js", "const opts = { introspection: true }"), "graphql-introspection") == nil {
		t.Error("graphql introspection not detected")
	}
}

func TestSAST_OffensiveRules(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.js", "cors({ origin: true, credentials: true })", "cors-wildcard-credentials"},
		{"a.js", "el.innerHTML = location.hash", "dom-xss"},
		{"a.js", "window.addEventListener('message', h)", "postmessage-no-origin"},
		{"a.js", "localStorage.setItem('jwt_token', t)", "token-in-localstorage"},
		{"a.js", "const l = 'https://' + req.headers.host", "host-header-trust"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_MoreOffensive(t *testing.T) {
	cases := []struct{ name, src, rule string }{
		{"a.js", "jwt.verify(t, k, { algorithms: ['HS256','RS256'] })", "jwt-alg-confusion"},
		{"a.js", "new ApolloServer({ schema })", "graphql-no-limits"},
		{"a.js", "const u = { ...req.body }", "js-spread-req-body"},
	}
	for _, c := range cases {
		if hasRule(scanSrc(t, c.name, c.src), c.rule) == nil {
			t.Errorf("%s: expected rule %q on %q", c.name, c.rule, c.src)
		}
	}
}

func TestSAST_OAuthAndSSRF(t *testing.T) {
	if hasRule(scanSrc(t, "a.js", "res.redirect(req.query.redirect_uri)"), "oauth-redirect-uri") == nil {
		t.Error("oauth redirect_uri not detected")
	}
	if hasRule(scanSrc(t, "a.js", "axios('http://169.254.169.254/' + p)"), "ssrf-internal-fetch") == nil {
		t.Error("ssrf internal fetch not detected")
	}
}

func TestSAST_CSharpRules(t *testing.T) {
	src := "using Microsoft.AspNetCore.Mvc;\n" +
		"public class VulnController : Controller\n" +
		"{\n" +
		"    [HttpGet(\"u/{id}\")]\n" +
		"    public IActionResult Get(string id) =>\n" +
		"        Ok(db.Database.ExecuteSqlRaw($\"SELECT * FROM U WHERE Id = {id}\"));\n" +
		"    [HttpPost(\"run\")]\n" +
		"    public IActionResult Run([FromForm] string cmd) { Process.Start(\"sh\", cmd); return Ok(); }\n" +
		"    [HttpGet(\"f\")]\n" +
		"    public IActionResult Read(string name) => Ok(File.ReadAllText(\"/d/\" + name));\n" +
		"    [HttpGet(\"go\")]\n" +
		"    public IActionResult Go(string url) => Redirect(url);\n" +
		"    public void Bad() { var f = new BinaryFormatter(); f.Deserialize(s); }\n" +
		"    public void Hash() { var h = MD5.Create(); }\n" +
		"}\n"
	fs := scanSrc(t, "VulnController.cs", src)
	for _, id := range []string{"cs-sql-raw", "cs-command-exec", "cs-path-traversal", "cs-open-redirect", "cs-insecure-deser", "cs-weak-hash"} {
		if hasRule(fs, id) == nil {
			t.Errorf("expected C# rule %q to fire; got %v", id, ruleIDs(fs))
		}
	}
	// Action parameters are user input: the SQLi must be marked reachable.
	if f := hasRule(fs, "cs-sql-raw"); f != nil && !f.Context.UserInput {
		t.Error("SQLi from an action parameter should be flagged UserInput (tainted)")
	}
}

func TestSAST_CSharpSafeQueriesNotFlagged(t *testing.T) {
	// Parameterised / interpolated-safe APIs must NOT be flagged as SQLi.
	src := "public class Repo {\n" +
		"  public void A(string id) { db.Database.FromSqlInterpolated($\"SELECT * FROM U WHERE Id = {id}\"); }\n" +
		"  public void B(string id) { var c = new SqlCommand(\"SELECT * FROM U WHERE Id = @id\"); c.Parameters.AddWithValue(\"@id\", id); }\n" +
		"}\n"
	fs := scanSrc(t, "Repo.cs", src)
	if f := hasRule(fs, "cs-sql-raw"); f != nil {
		t.Errorf("safe parameterised query wrongly flagged as SQLi at line %d", f.Line)
	}
}

func TestSAST_CSharpRazorXSS(t *testing.T) {
	fs := scanSrc(t, "View.cshtml", "<div>@Html.Raw(Model.Bio)</div>\n")
	if hasRule(fs, "cs-razor-raw") == nil {
		t.Errorf("expected cs-razor-raw to fire on @Html.Raw; got %v", ruleIDs(fs))
	}
}

func ruleIDs(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestSAST_CSharpDepthRules(t *testing.T) {
	src := "public class Sec : Controller {\n" +
		"  [HttpPost(\"s\")][IgnoreAntiforgeryToken]\n" +
		"  public IActionResult Save(User u) { TryUpdateModelAsync(u); return Ok(); }\n" +
		"  public void Cfg() {\n" +
		"    var opt = new CookieOptions { HttpOnly = false, Secure = false };\n" +
		"    var p = new TokenValidationParameters { ValidateIssuer = false };\n" +
		"    h.ServerCertificateCustomValidationCallback = (m,c,ch,e) => true;\n" +
		"    b.SetIsOriginAllowed(_ => true).AllowCredentials();\n" +
		"  }\n" +
		"}\n"
	fs := scanSrc(t, "Sec.cs", src)
	// cs-csrf-disabled is context-gated (needs global antiforgery), tested below.
	for _, id := range []string{
		"cs-mass-assignment", "cs-cookie-insecure",
		"cs-jwt-validation-disabled", "cs-cert-validation-disabled", "cs-cors-permissive",
	} {
		if hasRule(fs, id) == nil {
			t.Errorf("expected C# depth rule %q to fire; got %v", id, ruleIDs(fs))
		}
	}
}

func TestSAST_CSharpCSRFContextGated(t *testing.T) {
	controller := "public class C : Controller {\n" +
		"  [Microsoft.AspNetCore.Mvc.IgnoreAntiforgeryToken]\n" +
		"  public IActionResult X() => Ok();\n}\n"

	// No global antiforgery → [IgnoreAntiforgeryToken] is a no-op → NOT flagged.
	if hasRule(scanSrc(t, "C.cs", controller), "cs-csrf-disabled") != nil {
		t.Error("cs-csrf-disabled must stay silent without a global antiforgery filter (no-op attribute)")
	}

	// With a global AutoValidateAntiforgeryToken filter → it's a real opt-out.
	program := "builder.Services.AddControllersWithViews(o =>\n" +
		"  o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));\n"
	fs := scanFiles(t, map[string]string{"Program.cs": program, "C.cs": controller})
	if hasRule(fs, "cs-csrf-disabled") == nil {
		t.Errorf("cs-csrf-disabled should fire when global antiforgery is present; got %v", ruleIDs(fs))
	}
}

func scanFiles(t *testing.T, files map[string]string) []finding.Finding {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := New().Scan(dir, scanner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSAST_CSharpDepthNoFalsePositives(t *testing.T) {
	// Secure defaults must NOT be flagged.
	src := "public class Ok {\n" +
		"  public void Cfg() {\n" +
		"    var opt = new CookieOptions { HttpOnly = true, Secure = true };\n" +
		"    var p = new TokenValidationParameters { ValidateIssuer = true, ValidateLifetime = true };\n" +
		"    b.WithOrigins(\"https://trusted.example\").AllowCredentials();\n" +
		"  }\n" +
		"}\n"
	fs := scanSrc(t, "Ok.cs", src)
	for _, id := range []string{"cs-cookie-insecure", "cs-jwt-validation-disabled", "cs-cors-permissive"} {
		if f := hasRule(fs, id); f != nil {
			t.Errorf("secure config wrongly flagged by %q at line %d", id, f.Line)
		}
	}
}

func TestSAST_SensitiveDataInLogs(t *testing.T) {
	// Logging a sensitive VALUE (variable/interpolation/concat) must fire.
	positives := map[string]string{
		"a.js": "console.log('pw:', password);",
		"b.js": "logger.info(`token=${authToken}`);",
		"c.py": "print('key=' + api_key)",
		"d.cs": "_logger.LogInformation(\"secret {S}\", clientSecret);",
	}
	for name, src := range positives {
		if hasRule(scanSrc(t, name, src), "sensitive-data-log") == nil {
			t.Errorf("%s: expected sensitive-data-log to fire on %q", name, src)
		}
	}
	// Logging the WORD in a plain string, or a non-sensitive value, must not.
	negatives := map[string]string{
		"e.js": "console.log('password reset requested');",
		"f.js": "console.log(user.name);",
		"g.js": "console.log('done ' + orderId);",
	}
	for name, src := range negatives {
		if f := hasRule(scanSrc(t, name, src), "sensitive-data-log"); f != nil {
			t.Errorf("%s: false positive on %q (line %d)", name, src, f.Line)
		}
	}
}

func TestSAST_TLSVerifyDisabled(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.go", "cfg := &tls.Config{InsecureSkipVerify: true}"},
		{"b.py", "requests.get(u, verify=False)"},
		{"c.js", "new https.Agent({ rejectUnauthorized: false })"},
	} {
		if hasRule(scanSrc(t, c.name, c.src), "tls-verify-disabled") == nil {
			t.Errorf("%s: tls-verify-disabled not detected on %q", c.name, c.src)
		}
	}
	// Verification left ON must stay clean.
	if hasRule(scanSrc(t, "d.py", "requests.get(u, verify=True)"), "tls-verify-disabled") != nil {
		t.Error("verify=True must not be flagged")
	}
}

func TestSAST_ECBMode(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.py", "AES.new(key, AES.MODE_ECB)"},
		{"b.js", "crypto.createCipheriv('aes-256-ecb', key, null)"},
		{"c.cs", "aes.Mode = CipherMode.ECB;"},
	} {
		if hasRule(scanSrc(t, c.name, c.src), "ecb-mode") == nil {
			t.Errorf("%s: ecb-mode not detected on %q", c.name, c.src)
		}
	}
	if hasRule(scanSrc(t, "d.py", "AES.new(key, AES.MODE_GCM)"), "ecb-mode") != nil {
		t.Error("GCM must not be flagged as ECB")
	}
}

func TestSAST_ReDoS(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.py", `re.compile("(a+)+$")`},
		{"b.js", `new RegExp("(\\d*)*")`},
	} {
		if hasRule(scanSrc(t, c.name, c.src), "redos") == nil {
			t.Errorf("%s: redos not detected on %q", c.name, c.src)
		}
	}
	// Safe: linear regex, non-quantified group, and plain arithmetic with '/'.
	for _, c := range []struct{ name, src string }{
		{"c.py", `re.compile("^[a-z]+$")`},
		{"d.py", `re.compile("(abc)+")`},
		{"e.js", "const x = a / (b+c) * d;"},
	} {
		if hasRule(scanSrc(t, c.name, c.src), "redos") != nil {
			t.Errorf("%s: false ReDoS positive on %q", c.name, c.src)
		}
	}
}

func TestSAST_ZipSlipAndRubyDeser(t *testing.T) {
	if hasRule(scanSrc(t, "a.py", "t.extractall(dest)"), "zip-slip") == nil {
		t.Error("zip-slip (extractall) not detected")
	}
	if hasRule(scanSrc(t, "b.rb", "data = Marshal.load(payload)"), "ruby-insecure-deser") == nil {
		t.Error("Marshal.load not detected")
	}
	if hasRule(scanSrc(t, "c.rb", "YAML.load(input)"), "ruby-insecure-deser") == nil {
		t.Error("YAML.load not detected")
	}
	// safe_load must stay clean.
	if hasRule(scanSrc(t, "d.rb", "YAML.safe_load(input)"), "ruby-insecure-deser") != nil {
		t.Error("YAML.safe_load must not be flagged")
	}
}

func TestSAST_ReactDangerousHTML(t *testing.T) {
	if hasRule(scanSrc(t, "a.jsx", "<div dangerouslySetInnerHTML={{__html: h}} />"), "react-dangerous-html") == nil {
		t.Error("dangerouslySetInnerHTML not detected")
	}
	if hasRule(scanSrc(t, "b.jsx", "<div>{text}</div>"), "react-dangerous-html") != nil {
		t.Error("plain JSX must not be flagged")
	}
}
