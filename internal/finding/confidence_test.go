package finding

import "testing"

func boolp(b bool) *bool { return &b }

func TestConfidence(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want Confidence
	}{
		{"live secret", Finding{Kind: KindSecret, Context: Context{Validated: true, Live: true}}, Confirmed},
		{"placeholder secret", Finding{Kind: KindSecret, Context: Context{Placeholder: true}}, Tentative},
		{"entropy guess", Finding{Kind: KindSecret, RuleID: "generic-high-entropy"}, Tentative},
		{"typed secret offline", Finding{Kind: KindSecret, RuleID: "stripe-secret"}, Firm},
		{"tainted code sink", Finding{Kind: KindCode, File: "src/app.js", Context: Context{UserInput: true}}, Confirmed},
		{"pattern-only code", Finding{Kind: KindCode, File: "src/app.js"}, Firm},
		{"code in test file", Finding{Kind: KindCode, File: "src/app.test.js", Context: Context{UserInput: true}}, Tentative},
		{"reachable vuln", Finding{Kind: KindVuln, Context: Context{Reachable: boolp(true)}}, Confirmed},
	}
	for _, c := range cases {
		if got := c.f.Confidence(); got != c.want {
			t.Errorf("%s: Confidence = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	yes := []string{"a/b_test.go", "app.test.js", "x.spec.ts", "tests/foo.py", "__tests__/a.js", "src/AccountTests.cs", "test_utils.py"}
	for _, p := range yes {
		if !isTestPath(p) {
			t.Errorf("isTestPath(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"src/app.js", "internal/handler.go", "controllers/AccountController.cs"} {
		if isTestPath(p) {
			t.Errorf("isTestPath(%q) = true, want false", p)
		}
	}
}
