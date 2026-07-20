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

// ValidateMatch checks whether a detected secret is live and, if so, reads its
// blast radius. contextText is the surrounding document, used to find an AWS
// secret paired with an access key. validated is false when no validator exists.
func ValidateMatch(m RawMatch, contextText string, timeoutS int) (validated bool, res Result) {
	switch {
	case m.Validator == "":
		return false, Result{Note: "no live validator for this type yet"}
	case m.Validator == "aws":
		secret := findAWSSecret(contextText, m.Secret)
		if secret == "" {
			return false, Result{Note: "no paired secret key found near it — cannot verify"}
		}
		return true, awsValidateSTS(m.Secret, secret, timeoutS)
	case m.Validator == "twilio":
		token := findTwilioToken(contextText, m.Secret)
		if token == "" {
			return false, Result{Note: "no paired auth token found near it — cannot verify"}
		}
		return true, twilioValidate(m.Secret, token, timeoutS)
	default:
		return true, validate(m.Validator, m.Secret, timeoutS)
	}
}

// ApplyResult writes a validation Result onto a finding context (exported for
// the git-history scanner, which builds findings outside this package).
func ApplyResult(c *finding.Context, r Result) { applyResult(c, r) }

// Fix returns the remediation step for a secret rule.
func Fix(ruleID string) string { return secretFix(ruleID) }
