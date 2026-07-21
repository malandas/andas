package sast

import (
	"testing"

	"github.com/malandas/andas/internal/scanner"
)

func TestTaint_MultiHopFlow(t *testing.T) {
	lines := []string{
		"def handler(request):",
		"    cmd = request.args.get('x')", // source -> cmd tainted
		"    full = 'ping ' + cmd",        // cmd -> full tainted
		"    os.system(full)",             // sink references full
	}
	got := taintedLines(lines, ".py")
	if !got[3] {
		t.Error("taint should reach the sink on line 4 via cmd -> full")
	}
	if got[0] {
		t.Error("the def line has no user input")
	}
}

func TestTaint_ConstantNotTainted(t *testing.T) {
	lines := []string{"def clean():", "    os.system('ls -la')"}
	if taintedLines(lines, ".py")[1] {
		t.Error("a constant-arg command must not be marked tainted")
	}
}

func TestTaint_ResetsAtFunctionBoundary(t *testing.T) {
	lines := []string{
		"def a(request):",
		"    x = request.args.get('q')", // taints x within a()
		"def b():",                      // new function — taint resets
		"    os.system(x)",              // x here is a different scope; must NOT be tainted
	}
	if taintedLines(lines, ".py")[3] {
		t.Error("taint must not leak across the function boundary")
	}
}

func TestTaint_DirectSourceOnLine(t *testing.T) {
	lines := []string{"eval(request.args.get('c'))"}
	if !taintedLines(lines, ".py")[0] {
		t.Error("a source on the same line must count as tainted")
	}
}

func TestWholeToken(t *testing.T) {
	if wholeToken("os.system(fullpath)", "full") {
		t.Error("'full' must not match inside 'fullpath'")
	}
	if !wholeToken("os.system(full)", "full") {
		t.Error("'full' should match as a whole token")
	}
	if !wholeToken("echo $foo;", "$foo") {
		t.Error("PHP $foo should match as a whole token")
	}
	if wholeToken("echo $foobar;", "$foo") {
		t.Error("$foo must not match inside $foobar")
	}
}

func TestTaint_TransitiveAcrossCalls(t *testing.T) {
	// user input flows handler -> step1(var) -> step2(var) -> sink.
	// The old single-hop tracker stopped at step1; the fixpoint reaches step2.
	lines := []string{
		"function handler(req, res) {",
		"  const uid = req.query.uid;",
		"  step1(uid);",
		"}",
		"function step1(a) {",
		"  step2(a);",
		"}",
		"function step2(b) {",
		"  db.query('SELECT ' + b);",
		"}",
	}
	got := taintedLines(lines, ".js")
	if !got[8] {
		t.Error("taint should reach the sink two calls deep (step2 body)")
	}
}

func TestTaint_FastPathNoSource(t *testing.T) {
	// A file with no user-input source must return all-false (and not loop).
	lines := []string{
		"function add(a, b) {",
		"  const total = a + b;",
		"  return db.query('SELECT 1');",
		"}",
	}
	got := taintedLines(lines, ".js")
	for i, v := range got {
		if v {
			t.Errorf("line %d flagged tainted with no source in the file", i+1)
		}
	}
}

func TestTaint_ControlFlowNotACallee(t *testing.T) {
	// `if (userInput)` must not taint an unrelated function body via the keyword.
	lines := []string{
		"function h(req) {",
		"  if (req.query.x) { return; }",
		"  return 1;",
		"}",
		"function unrelated(y) {",
		"  return exec(y);",
		"}",
	}
	got := taintedLines(lines, ".js")
	if got[5] {
		t.Error("`if` must not propagate taint into an unrelated function")
	}
}

func TestCrossFileTaint_ControllerToService(t *testing.T) {
	files := []scanner.TextFile{
		{Path: "OrdersController.cs", Lines: []string{
			"[Route(\"orders\")]",
			"public class OrdersController(IOrderService svc) : ControllerBase {",
			"  [HttpGet(\"{id}\")]",
			"  public IActionResult Get(string id) { return Ok(svc.LoadOrder(id)); }",
			"}",
		}},
		{Path: "OrderService.cs", Lines: []string{
			"public class OrderService {",
			"  public Order LoadOrder(string orderId) {",
			"    return db.Database.ExecuteSqlRaw($\"SELECT * FROM Orders WHERE Id = {orderId}\");",
			"  }",
			"}",
		}},
	}
	tb := crossFileTaint(files)
	ft := tb["OrderService.cs"]
	if !ft.tainted[2] {
		t.Error("taint should reach the SQL sink in OrderService via the controller's action param")
	}
}

func TestCrossFileTaint_UniquenessGuard(t *testing.T) {
	// `Get` is defined in two files → ambiguous → taint must NOT propagate.
	files := []scanner.TextFile{
		{Path: "A.cs", Lines: []string{
			"public class A {",
			"  public IActionResult Handle(string x) { return svc.Get(x); }", // Get called with tainted-ish
			"}",
		}},
		{Path: "B.cs", Lines: []string{
			"public class B {",
			"  public string Get(string y) { return db.Database.ExecuteSqlRaw($\"X {y}\"); }",
			"}",
		}},
	}
	tb := crossFileTaint(files)
	if tb["B.cs"].tainted[1] {
		t.Error("a non-uniquely-defined method (Get x2) must not receive cross-file taint")
	}
}

func TestCrossFileTaint_NoSourceFilesAllFalse(t *testing.T) {
	files := []scanner.TextFile{
		{Path: "util.js", Lines: []string{"function add(a,b){ return a+b; }", "const z = add(1,2);"}},
	}
	tb := crossFileTaint(files)
	for i, v := range tb["util.js"].tainted {
		if v {
			t.Errorf("no-source file line %d wrongly tainted", i)
		}
	}
}

func TestTaint_NumericSanitizerClearsTaint(t *testing.T) {
	// parseInt neutralises the value → the sink is no longer user-controlled.
	sanitized := []string{
		"function h(req){",
		"  const id = parseInt(req.query.id);",
		"  db.query('SELECT ' + id);",
		"}",
	}
	if taintedLines(sanitized, ".js")[2] {
		t.Error("value coerced via parseInt must not be tainted at the sink")
	}
	// Without the coercion, the same flow IS tainted.
	raw := []string{
		"function h(req){",
		"  const id = req.query.id;",
		"  db.query('SELECT ' + id);",
		"}",
	}
	if !taintedLines(raw, ".js")[2] {
		t.Error("raw user input should still reach the sink")
	}
}

func TestTaint_StringCoercionIsNotSanitizer(t *testing.T) {
	// String()/toString keep the payload — must stay tainted.
	lines := []string{
		"function h(req){",
		"  const s = String(req.query.q);",
		"  el.innerHTML = s;",
		"}",
	}
	if !taintedLines(lines, ".js")[2] {
		t.Error("String() is not a sanitizer; taint must persist")
	}
}

func TestTaint_CSharpIntParseSanitizes(t *testing.T) {
	lines := []string{
		"public IActionResult G(string id) {",
		"  var n = int.Parse(id);",
		"  return Ok(db.Database.ExecuteSqlRaw($\"WHERE Id = {n}\"));",
		"}",
	}
	// Seed id as an action param via crossFileTaint-style single file.
	got := taintedLines(append([]string{"[HttpGet(\"u/{id}\")]"}, lines...), ".cs")
	if got[3] {
		t.Error("int.Parse must sanitize the C# action parameter before the sink")
	}
}

func TestXSSSanitizer_ContextAware(t *testing.T) {
	// HTML-encoded value → the XSS sink is not exploitable.
	enc := []string{
		"function r(req){",
		"  const name = encodeURIComponent(req.query.name);",
		"  el.innerHTML = name;",
		"}",
	}
	ft := crossFileTaint([]scanner.TextFile{{Path: "a.js", Lines: enc}})["a.js"]
	if ft.tainted[2] && !ft.htmlSafe[2] {
		t.Error("HTML-encoded value must be marked htmlSafe at the XSS sink")
	}
	// The SAME encoder must NOT clear taint for a SQL sink (wrong context).
	sql := []string{
		"function q(req){",
		"  const id = encodeURIComponent(req.query.id);",
		"  db.query('SELECT ' + id);",
		"}",
	}
	fq := crossFileTaint([]scanner.TextFile{{Path: "q.js", Lines: sql}})["q.js"]
	if !fq.tainted[2] {
		t.Error("URL-encoding does not sanitise SQL — the value must stay tainted")
	}
	if fq.htmlSafe[2] {
		// htmlSafe may be true, but sast.go only applies it to CWE-79 — so the
		// SQL finding stays. Documented here: htmlSafe is context-scoped downstream.
	}
}

func TestFlowOrigin_TracesToSource(t *testing.T) {
	lines := []string{
		"function h(req){",             // 1
		"  const x = req.query.id;",    // 2  ← source
		"  const y = 'a' + x;",         // 3  ← propagate
		"  db.query('SELECT ' + y);",   // 4  ← sink
		"}",
	}
	ft := crossFileTaint([]scanner.TextFile{{Path: "f.js", Lines: lines}})["f.js"]
	if !ft.tainted[3] {
		t.Fatal("sink line should be tainted")
	}
	if ft.origin[3] != 2 {
		t.Errorf("flow origin = line %d, want 2 (the req.query source)", ft.origin[3])
	}
}
