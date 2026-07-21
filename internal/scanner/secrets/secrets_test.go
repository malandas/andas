package secrets

import (
	"strings"
	"testing"
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
