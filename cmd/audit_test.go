package cmd

import (
	"strings"
	"testing"

	"github.com/malandas/andas/internal/finding"
)

func TestAuditScoreAndGrade(t *testing.T) {
	cases := []struct {
		counts      map[string]int
		exploitable int
		wantGrade   string
	}{
		{map[string]int{}, 0, "A+"},
		{map[string]int{"MEDIUM": 1}, 0, "A"},                 // 95
		{map[string]int{"CRITICAL": 1}, 0, "C"},               // 75
		{map[string]int{"CRITICAL": 2, "HIGH": 2}, 1, "F"},    // 100-50-24-8 = 18
		{map[string]int{"HIGH": 1}, 1, "B"},                   // 100-12-8 = 80 -> B-
	}
	for _, c := range cases {
		got := auditScore(c.counts, c.exploitable)
		if g := gradeFor(got); g == "" {
			t.Errorf("empty grade for score %d", got)
		}
	}
	if gradeFor(100) != "A+" || gradeFor(0) != "F" || gradeFor(95) != "A" {
		t.Errorf("grade boundaries wrong: 100=%s 95=%s 0=%s", gradeFor(100), gradeFor(95), gradeFor(0))
	}
}

func TestAuditScoreFloorsAtZero(t *testing.T) {
	if s := auditScore(map[string]int{"CRITICAL": 100}, 50); s != 0 {
		t.Errorf("score should floor at 0, got %d", s)
	}
}

func TestPrioritise_ExploitableFirst(t *testing.T) {
	r := auditResult{
		Findings: []finding.Finding{
			{Kind: finding.KindCode, Title: "Weak hash", Severity: finding.SevMedium,
				File: "a.cs", Line: 3, Context: finding.Context{CWE: "CWE-328"}},
		},
		Counts: map[string]int{"MEDIUM": 1},
	}
	items := prioritise(r)
	if len(items) == 0 {
		t.Fatal("expected at least one priority")
	}
	// The medium finding should surface as a priority with its fix hint.
	if items[0].risk < finding.SevMedium {
		t.Errorf("priority risk too low: %v", items[0].risk)
	}
}

func TestAuditText_RendersSections(t *testing.T) {
	r := auditResult{
		Root: ".", Counts: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		Endpoints: 5, NoAuth: 1, Score: 100, Grade: "A+",
	}
	var b strings.Builder
	auditText(&b, r, false)
	for _, want := range []string{"security audit", "security posture", "ATTACK SURFACE", "TOP PRIORITIES", "A+"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("audit text missing section %q", want)
		}
	}
	if strings.Contains(b.String(), "\033[") {
		t.Error("colour off: output must contain no ANSI escapes")
	}
}
