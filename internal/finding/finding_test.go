package finding

import "testing"

func boolPtr(b bool) *bool { return &b }

func TestRealRisk_Secret(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want Severity
	}{
		{
			name: "live secret is always critical",
			f:    Finding{Kind: KindSecret, Severity: SevHigh, Context: Context{Validated: true, Live: true}},
			want: SevCritical,
		},
		{
			name: "dead secret is demoted to info",
			f:    Finding{Kind: KindSecret, Severity: SevHigh, Context: Context{Validated: true, Live: false}},
			want: SevInfo,
		},
		{
			name: "unvalidated secret keeps its base severity",
			f:    Finding{Kind: KindSecret, Severity: SevHigh, Context: Context{Validated: false}},
			want: SevHigh,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.RealRisk(); got != c.want {
				t.Errorf("RealRisk() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRealRisk_Vuln(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want Severity
	}{
		{
			name: "reachable vuln keeps full weight",
			f:    Finding{Kind: KindVuln, Severity: SevCritical, Context: Context{Reachable: boolPtr(true)}},
			want: SevCritical,
		},
		{
			name: "unreachable vuln is demoted to low",
			f:    Finding{Kind: KindVuln, Severity: SevCritical, Context: Context{Reachable: boolPtr(false)}},
			want: SevLow,
		},
		{
			name: "unanalysed vuln keeps base severity",
			f:    Finding{Kind: KindVuln, Severity: SevHigh, Context: Context{Reachable: nil}},
			want: SevHigh,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.RealRisk(); got != c.want {
				t.Errorf("RealRisk() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"ghp_1234567890abcdefghij": "ghp_******ij",
		"short":                    "*****",
		"":                         "",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	// A redaction must never leak the middle of the secret. (Built from split
	// literals so andas doesn't flag its own test file when scanning itself.)
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	if r := Redact(secret); r == secret {
		t.Error("Redact returned the secret unchanged")
	}
}

func TestFingerprint_StableAndDistinct(t *testing.T) {
	a := Finding{RuleID: "github-pat", File: "config.js", Line: 3, Match: "ghp_******ij"}
	if a.Fingerprint() != a.Fingerprint() {
		t.Error("Fingerprint is not stable across calls")
	}
	// A different line is a different finding.
	b := a
	b.Line = 4
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("Fingerprint collided across different lines")
	}
}
