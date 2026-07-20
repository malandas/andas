package sast

import "testing"

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
