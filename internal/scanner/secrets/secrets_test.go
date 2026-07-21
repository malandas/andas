package secrets

import (
	"strings"
	"testing"

	"github.com/malandas/andas/internal/finding"
)

// Sample tokens are assembled from split literals so this source file never
// contains a contiguous provider-format secret — which would (rightly) trip
// GitHub push-protection and andas itself. At runtime they are whole tokens,
// so they still exercise the detection rules.
var (
	sampleGitHub = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	sampleStripe = "sk_live_" + "51H8xLmNoPqRsTuVwXyZ1234abcd"
	sampleAWS    = "AKIA" + "IOSFODNN7EXAMPLE"
)

func TestShannonEntropy(t *testing.T) {
	// A single repeated character has zero entropy; a varied string has more.
	if e := shannonEntropy("aaaaaaaa"); e != 0 {
		t.Errorf("entropy of uniform string = %v, want 0", e)
	}
	if lo, hi := shannonEntropy("password"), shannonEntropy("x9K2mQ7vBnL4pR8w"); lo >= hi {
		t.Errorf("random token entropy (%v) should exceed a word's (%v)", hi, lo)
	}
}

func TestIsLikelySecret(t *testing.T) {
	positives := []string{
		"x9K2mQ7vBnL4pR8wZ3jF6tY1sH5dG0cA",
		"kJ8mN2pQ9vX4wL7bR3tZ6",
	}
	for _, v := range positives {
		if !isLikelySecret(v) {
			t.Errorf("isLikelySecret(%q) = false, want true", v)
		}
	}
	negatives := map[string]string{
		"your_api_key_here":   "placeholder wording",
		"hello world welcome": "low entropy / spaces excluded upstream",
		"aaaaaaaaaaaaaaaa":    "no entropy",
		"short":               "too short",
		"changeme12345678":    "placeholder wording",
		sampleGitHub:          "already caught by a typed rule",
	}
	for v, why := range negatives {
		if isLikelySecret(v) {
			t.Errorf("isLikelySecret(%q) = true, want false (%s)", v, why)
		}
	}
}

func TestDetect_KnownRules(t *testing.T) {
	content := []byte("token = \"" + sampleGitHub + "\"\nstripe = \"" + sampleStripe + "\"\n")
	got := Detect(content, false)
	found := map[string]bool{}
	for _, m := range got {
		found[m.RuleID] = true
	}
	for _, want := range []string{"github-pat", "stripe-secret"} {
		if !found[want] {
			t.Errorf("Detect did not find rule %q", want)
		}
	}
}

func TestDetect_EntropyToggle(t *testing.T) {
	// Assembled from split literals so the line isn't a contiguous secret
	// assignment in source — andas shouldn't flag its own test file.
	content := []byte("const apiSecret = " + `"` + "aZ3kP9mW7vT2nQ8xR5jL4hB6dF1sG0yC" + `";`)
	if hits := Detect(content, false); len(hits) != 0 {
		t.Errorf("entropy disabled: got %d hits, want 0", len(hits))
	}
	hits := Detect(content, true)
	if len(hits) != 1 || hits[0].RuleID != genericRuleID {
		t.Errorf("entropy enabled: got %+v, want one %s hit", hits, genericRuleID)
	}
}

// Guard against a rule regex that is accidentally too broad or too narrow.
func TestRules_MatchSamples(t *testing.T) {
	samples := map[string]string{
		"github-pat":     sampleGitHub,
		"aws-access-key": sampleAWS,
		"stripe-secret":  sampleStripe,
	}
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	for id, sample := range samples {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("rule %q not found", id)
		}
		if !r.Pattern.MatchString(sample) {
			t.Errorf("rule %q did not match its own sample %q", id, sample)
		}
	}
	// A rule must not match ordinary prose.
	prose := "the quick brown fox jumps over the lazy dog"
	for _, r := range rules {
		if r.Pattern.MatchString(prose) {
			t.Errorf("rule %q matched ordinary prose", r.ID)
		}
	}
}

func TestSecretFix_AlwaysActionable(t *testing.T) {
	for _, r := range rules {
		if fix := secretFix(r.ID); !strings.ContainsAny(fix, "abcdefghijklmnopqrstuvwxyz") {
			t.Errorf("rule %q has an empty/blank fix", r.ID)
		}
	}
}

func TestDetect_ConnectionAndWeakPassword(t *testing.T) {
	content := []byte("db=\"postgres://admin:s3cr3tpass@10.0.0.5/prod\"\npassword = \"admin\"\n")
	found := map[string]bool{}
	for _, m := range Detect(content, false) {
		found[m.RuleID] = true
	}
	for _, want := range []string{"connection-string-creds", "weak-default-password"} {
		if !found[want] {
			t.Errorf("Detect missed %q", want)
		}
	}
}

func TestDetect_DiscordAndNotJWT(t *testing.T) {
	// A Discord bot token is detected…
	bot := "MTA123456789012345678901.Gh3jKl.abcdefghijklmnopqrstuvwxyz0"
	found := map[string]bool{}
	for _, m := range Detect([]byte("token = \""+bot+"\""), false) {
		found[m.RuleID] = true
	}
	if !found["discord-bot-token"] {
		t.Error("Discord bot token not detected")
	}
	// …but a JWT (three base64 parts starting eyJ) is NOT mistaken for one.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmnopqrstuvwxyz012"
	for _, m := range Detect([]byte("jwt = \""+jwt+"\""), false) {
		if m.RuleID == "discord-bot-token" {
			t.Error("a JWT was misdetected as a Discord token")
		}
	}
}

func TestValidateDiscord_DeadKey(t *testing.T) {
	// classify handles the non-live path without a network dependency in CI;
	// here we just ensure the validator is wired and returns a Result.
	r := validate("discord", "not-a-real-token", 1)
	if r.Live {
		t.Error("a bogus token must not validate as live")
	}
}

func TestDetect_NewProviders(t *testing.T) {
	samples := map[string]string{
		"anthropic-key": "sk-ant-api03-" + strings.Repeat("a", 84),
		"doppler-token": "dp.pt." + strings.Repeat("b", 43),
		"square-token":  "EAAA" + strings.Repeat("c", 60),
		"hubspot-token": "pat-na1-" + "12345678-1234-1234-1234-123456789012",
		"mailchimp-key": strings.Repeat("a", 32) + "-us21",
		"linear-key":    "lin_api_" + strings.Repeat("d", 40),
	}
	for id, tok := range samples {
		found := false
		for _, m := range Detect([]byte("k = \""+tok+"\""), false) {
			if m.RuleID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not detected for sample %q", id, tok)
		}
	}
	// None of these rules may match ordinary prose.
	prose := "the quick brown fox jumps over the lazy dog many times over"
	for _, m := range Detect([]byte(prose), false) {
		switch m.RuleID {
		case "anthropic-key", "doppler-token", "square-token", "hubspot-token", "mailchimp-key", "linear-key":
			t.Errorf("%s matched ordinary prose", m.RuleID)
		}
	}
}

func TestIsPlaceholder(t *testing.T) {
	yes := []string{"REPLACE_ME", "your-api-key-here", "AKIAIOSFODNN7EXAMPLE", "<your-token>", "${SECRET}", "changeme", "xxxxxxxxxxxx", "aaaaaaaaaaaa", "dummy_value_1234"}
	for _, s := range yes {
		if !isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) = false, want true", s)
		}
	}
	no := []string{"sk_live_" + "51H8xLmNoPqRsTuVwXyZ1234abcd", "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz", "aZ3kP9mW7vT2nQ8xR5jL4hB6dF1sG0yC"}
	for _, s := range no {
		if isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) = true, want false (real secret)", s)
		}
	}
}

func TestPlaceholderSecretDemotedToInfo(t *testing.T) {
	// A secret finding marked as a placeholder must resolve to INFO (noise),
	// regardless of its rule severity.
	f := finding.Finding{
		Kind:     finding.KindSecret,
		Severity: finding.SevCritical,
		Context:  finding.Context{Placeholder: true},
	}
	if f.RealRisk() != finding.SevInfo {
		t.Errorf("placeholder secret RealRisk = %v, want INFO", f.RealRisk())
	}
	// A non-placeholder, unvalidated secret keeps its rule severity.
	real := finding.Finding{Kind: finding.KindSecret, Severity: finding.SevCritical}
	if real.RealRisk() != finding.SevCritical {
		t.Errorf("real secret RealRisk = %v, want CRITICAL", real.RealRisk())
	}
}
