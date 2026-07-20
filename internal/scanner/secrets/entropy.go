package secrets

import (
	"math"
	"regexp"
	"strings"
)

// Known regex rules only catch credentials shaped like a provider's format.
// Custom, internal, or one-off secrets slip through. Entropy detection fills
// that gap: a long, high-randomness string assigned to a secret-looking name is
// probably a secret even if we've never seen its shape. It is inherently
// heuristic, so these findings are unverifiable MEDIUM by default — and the
// baseline mode exists precisely to silence any false positives.

// reAssign matches `name = "value"` / `name: "value"` where the name looks like
// it holds a credential and the value is a solid, quoted token.
var reAssign = regexp.MustCompile(
	`(?i)([A-Za-z0-9_.\-]*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|access[_-]?key|auth|credential|priv(?:ate)?[_-]?key)[A-Za-z0-9_.\-]*)\s*[:=]\s*['"]([^'"\s]{12,})['"]`)

// placeholderHints are giveaways that a value is a sample, not a real secret.
var placeholderHints = []string{
	"example", "changeme", "your_", "yourkey", "placeholder", "dummy",
	"sample", "redacted", "xxxx", "<", ">", "...", "process.env", "${",
	"insert", "todo", "fixme", "notreal", "fake",
}

const entropyThreshold = 3.2 // bits/char; random tokens sit well above this

// entropyValues returns the quoted values in text that look like real secrets
// by the heuristic above. Used by both the file scan and the history scan.
func entropyValues(text string) []string {
	var out []string
	for _, m := range reAssign.FindAllStringSubmatch(text, -1) {
		if v := m[2]; isLikelySecret(v) {
			out = append(out, v)
		}
	}
	return out
}

// isLikelySecret applies the precision filters: real entropy, not a placeholder,
// and not something a known rule already reports (to avoid double-counting).
func isLikelySecret(value string) bool {
	if len(value) < 12 {
		return false
	}
	low := strings.ToLower(value)
	for _, h := range placeholderHints {
		if strings.Contains(low, h) {
			return false
		}
	}
	if shannonEntropy(value) < entropyThreshold {
		return false
	}
	for _, rule := range rules { // a typed rule will report it with more detail
		if rule.Pattern.MatchString(value) {
			return false
		}
	}
	return true
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var e float64
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}
