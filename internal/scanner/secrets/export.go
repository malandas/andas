package secrets

import "github.com/malandas/andas/internal/finding"

// This file exposes the secret-detection machinery for reuse by other scanners
// (notably git-history), so the rules and validators live in exactly one place.

// RawMatch is a detected secret before validation.
type RawMatch struct {
	RuleID    string
	Title     string
	Secret    string
	Validator string
	Severity  finding.Severity
}

// Detect runs every secret rule over content and returns the raw matches. When
// entropy is true it also includes high-entropy secret-like values that no
// typed rule matched.
func Detect(content []byte, entropy bool) []RawMatch {
	text := string(content)
	var out []RawMatch
	for _, rule := range rules {
		for _, m := range rule.Pattern.FindAllString(text, -1) {
			out = append(out, RawMatch{
				RuleID:    rule.ID,
				Title:     rule.Title,
				Secret:    m,
				Validator: rule.Validator,
				Severity:  rule.Severity,
			})
		}
	}
	if entropy {
		for _, v := range entropyValues(text) {
			out = append(out, RawMatch{
				RuleID:   genericRuleID,
				Title:    "High-entropy secret-like value",
				Secret:   v,
				Severity: finding.SevMedium,
			})
		}
	}
	return out
}

// ValidateMatch checks whether a detected secret is live. contextText is the
// surrounding document, used to find an AWS secret paired with an access key.
func ValidateMatch(m RawMatch, contextText string, timeoutS int) (validated, live bool, note string) {
	switch {
	case m.Validator == "":
		return false, false, "no live validator for this type yet"
	case m.Validator == "aws":
		secret := findAWSSecret(contextText, m.Secret)
		if secret == "" {
			return false, false, "no paired secret key found near it — cannot verify"
		}
		live, note = awsValidateSTS(m.Secret, secret, timeoutS)
		return true, live, note
	default:
		live, note = validate(m.Validator, m.Secret, timeoutS)
		return true, live, note
	}
}

// Fix returns the remediation step for a secret rule.
func Fix(ruleID string) string { return secretFix(ruleID) }
