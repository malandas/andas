package secrets

import "regexp"

// placeholderRe matches the wording that marks a template/dummy value rather
// than a real credential — the noise that fills example configs and docs.
var placeholderRe = regexp.MustCompile(`(?i)replace|change[_-]?me|your[_-]?(?:api|key|token|secret|password|id)|placeholder|example|dummy|sample|redacted|insert[_-]?(?:your|key|token|here)|todo|fixme|not[_-]?real|fake[_-]?(?:key|token|secret)|xxxx|<[a-z_]|\{\{|\$\{`)

// isPlaceholder reports whether a matched secret value is an obvious
// placeholder — template wording, an angle/brace token, or a single character
// repeated — so it can be demoted out of the real-risk report.
func isPlaceholder(s string) bool {
	if placeholderRe.MatchString(s) {
		return true
	}
	// A run of one repeated character (aaaaaaaa, 00000000).
	if len(s) >= 6 {
		same := true
		for i := 1; i < len(s); i++ {
			if s[i] != s[0] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}
