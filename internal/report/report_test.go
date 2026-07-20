package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/malandas/andas/internal/finding"
)

func TestSarifLevel(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SevCritical: "error",
		finding.SevHigh:     "error",
		finding.SevMedium:   "warning",
		finding.SevLow:      "note",
		finding.SevInfo:     "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%v) = %q, want %q", sev, got, want)
		}
	}
}

func TestBaseline_RoundTripAndFilter(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "github-pat", File: "a.js", Line: 1, Match: "ghp_******ij"},
		{RuleID: "stripe-secret", File: "b.js", Line: 2, Match: "sk_l******cd"},
	}
	path := filepath.Join(t.TempDir(), "baseline.json")

	if err := WriteBaseline(path, findings, time.Unix(0, 0)); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	// Everything in the baseline is suppressed...
	kept, suppressed := b.Filter(findings)
	if suppressed != 2 || len(kept) != 0 {
		t.Errorf("Filter of baselined findings: kept=%d suppressed=%d, want 0/2", len(kept), suppressed)
	}

	// ...but a brand-new finding survives.
	newF := finding.Finding{RuleID: "aws-access-key", File: "c.js", Line: 9, Match: "AKIA******LE"}
	kept, suppressed = b.Filter(append(findings, newF))
	if suppressed != 2 || len(kept) != 1 || kept[0].RuleID != "aws-access-key" {
		t.Errorf("Filter with a new finding: kept=%v suppressed=%d, want the new one only", kept, suppressed)
	}
}

func TestBaseline_StoresNoSecretMaterial(t *testing.T) {
	// The baseline must persist only the redacted match, never raw secrets.
	findings := []finding.Finding{{RuleID: "github-pat", File: "a.js", Line: 1, Match: "ghp_******ij"}}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := WriteBaseline(path, findings, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	b, _ := LoadBaseline(path)
	for _, e := range b.Entries {
		if e.Note != "" && len(e.Note) > 0 && !containsMask(e.Note) {
			t.Errorf("baseline entry note %q looks unredacted", e.Note)
		}
	}
}

func containsMask(s string) bool {
	for _, r := range s {
		if r == '*' {
			return true
		}
	}
	return false
}

func TestMissingBaselineIsEmptyNotError(t *testing.T) {
	b, err := LoadBaseline(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing baseline should not error, got %v", err)
	}
	if _, suppressed := b.Filter([]finding.Finding{{RuleID: "x"}}); suppressed != 0 {
		t.Errorf("empty baseline suppressed %d, want 0", suppressed)
	}
}

func TestRank_PrivilegedLiveSecretsFirst(t *testing.T) {
	// Two live secrets (both CRITICAL). The high-privilege one must sort first.
	plain := finding.Finding{Kind: finding.KindSecret, Title: "plain",
		Context: finding.Context{Validated: true, Live: true, Privileged: false}}
	admin := finding.Finding{Kind: finding.KindSecret, Title: "admin",
		Context: finding.Context{Validated: true, Live: true, Privileged: true}}

	rows := rank([]finding.Finding{plain, admin})
	if rows[0].f.Title != "admin" {
		t.Errorf("expected the high-privilege secret first, got %q", rows[0].f.Title)
	}
}

func TestHTML_RendersBlastRadius(t *testing.T) {
	f := finding.Finding{
		Kind: finding.KindSecret, Title: "GitHub PAT", File: "a.js", Line: 1, Match: "ghp_***",
		Context: finding.Context{Validated: true, Live: true, Identity: "octocat",
			Access: []string{"repo", "admin:org"}, Privileged: true},
	}
	var b strings.Builder
	if err := HTML(&b, []finding.Finding{f}, "."); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"octocat", "admin:org", "HIGH-PRIVILEGE"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}
