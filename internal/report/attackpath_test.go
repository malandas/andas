package report

import (
	"strings"
	"testing"

	"github.com/malandas/andas/internal/finding"
)

func liveSecret(rule, ident string, priv bool, file string) finding.Finding {
	return finding.Finding{Kind: finding.KindSecret, RuleID: rule, File: file,
		Context: finding.Context{Validated: true, Live: true, Identity: ident, Privileged: priv}}
}

func TestAttackPath_NoLiveNoChain(t *testing.T) {
	// A dead secret must not produce an attack narrative.
	dead := finding.Finding{Kind: finding.KindSecret, RuleID: "github-pat",
		Context: finding.Context{Validated: true, Live: false}}
	if ap := AttackPath([]finding.Finding{dead}); ap != nil {
		t.Errorf("dead secret produced an attack path: %v", ap)
	}
}

func TestAttackPath_PrivilegedAndMultiProvider(t *testing.T) {
	fs := []finding.Finding{
		liveSecret("github-pat", "octocat", true, "a.js"),
		liveSecret("aws-access-key", "arn:...:root", true, "b.js"),
	}
	ap := AttackPath(fs)
	joined := strings.Join(ap, "\n")
	if !strings.Contains(joined, "high-privilege GitHub") {
		t.Errorf("missing GitHub privilege line: %v", ap)
	}
	if !strings.Contains(joined, "Multiple live credentials") {
		t.Errorf("missing multi-provider chain line: %v", ap)
	}
}

func TestAttackPath_HistoryLive(t *testing.T) {
	fs := []finding.Finding{liveSecret("stripe-secret", "acct_1", false, "git history @ abc (x, 2025-01-01)")}
	ap := AttackPath(fs)
	if !strings.Contains(strings.Join(ap, "\n"), "still live in git history") {
		t.Errorf("missing history-live line: %v", ap)
	}
}

func TestMarkdown_TableAndEscaping(t *testing.T) {
	fs := []finding.Finding{
		{Kind: finding.KindVuln, Title: "pkg | with pipe", File: "package.json", Severity: finding.SevHigh,
			Context: finding.Context{Reachable: boolTrue()}},
	}
	var b strings.Builder
	if err := Markdown(&b, fs); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "andas security report") || !strings.Contains(out, "HIGH") {
		t.Errorf("markdown missing header/row: %s", out)
	}
	if strings.Contains(out, "pkg | with pipe") {
		t.Error("pipe in title was not escaped — breaks the table")
	}
}

func boolTrue() *bool { b := true; return &b }
