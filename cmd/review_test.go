package cmd

import (
	"strings"
	"testing"

	"github.com/malandas/andas/internal/finding"
)

func fnd(file string, line int, sev finding.Severity, kind finding.Kind, title string) finding.Finding {
	return finding.Finding{File: file, Line: line, Severity: sev, Kind: kind, Title: title}
}

func TestBuildReview_GroupsAndRanks(t *testing.T) {
	all := []finding.Finding{
		fnd("a.js", 10, finding.SevMedium, finding.KindCode, "sqli"),
		fnd("b.js", 2, finding.SevCritical, finding.KindSecret, "key"),
		fnd("a.js", 3, finding.SevHigh, finding.KindCode, "cmd"),
	}
	rev := buildReview(all)
	// File with the CRITICAL should come first.
	if rev.files[0].path != "b.js" {
		t.Errorf("most severe file should sort first, got %s", rev.files[0].path)
	}
	// Within a.js, HIGH (line 3) before MEDIUM (line 10).
	var af reviewFile
	for _, rf := range rev.files {
		if rf.path == "a.js" {
			af = rf
		}
	}
	if af.findings[0].Title != "cmd" {
		t.Errorf("higher-risk finding should sort first within a file, got %s", af.findings[0].Title)
	}
	if rev.highest != finding.SevCritical {
		t.Errorf("highest = %v, want CRITICAL", rev.highest)
	}
}

func TestReviewVerdict(t *testing.T) {
	cases := []struct {
		highest finding.Severity
		total   int
		wantReq bool
	}{
		{finding.SevInfo, 0, false},   // clean → approve
		{finding.SevHigh, 3, true},    // high → request changes
		{finding.SevCritical, 1, true},
		{finding.SevMedium, 2, false}, // medium → comment, not blocking
		{finding.SevLow, 1, false},
	}
	for _, c := range cases {
		icon, text := reviewVerdict(c.highest, c.total)
		isReq := strings.Contains(text, "REQUEST CHANGES")
		if isReq != c.wantReq {
			t.Errorf("verdict(%v,%d): requestChanges=%v want %v (%s %s)", c.highest, c.total, isReq, c.wantReq, icon, text)
		}
	}
}

func TestReviewMarkdown_Postable(t *testing.T) {
	rev := buildReview([]finding.Finding{
		fnd("config.js", 2, finding.SevCritical, finding.KindSecret, "Stripe key"),
	})
	var b strings.Builder
	if err := reviewMarkdown(&b, rev, "the whole project"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"security code review", "REQUEST CHANGES", "config.js", "Stripe key", "CRITICAL"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestReviewTLDR(t *testing.T) {
	// Clean change.
	if got := reviewTLDR(buildReview(nil)); !strings.Contains(got, "no new security risk") {
		t.Errorf("clean TLDR wrong: %q", got)
	}
	// With findings — names the top issue and counts.
	rev := buildReview([]finding.Finding{
		fnd("config.js", 2, finding.SevCritical, finding.KindSecret, "Stripe key"),
		fnd("app.js", 5, finding.SevMedium, finding.KindCode, "sqli"),
	})
	got := reviewTLDR(rev)
	for _, want := range []string{"1 critical", "1 medium", "Stripe key", "config.js:2"} {
		if !strings.Contains(got, want) {
			t.Errorf("TLDR missing %q: %q", want, got)
		}
	}
}
