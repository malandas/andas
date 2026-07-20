package secrets

import (
	"regexp"

	"github.com/malandas/andas/internal/finding"
)

// Rule is one secret-detection pattern. Validator names the live-check to run
// (see validators in validate.go); an empty Validator means we can detect the
// secret but cannot yet prove whether it is live.
type Rule struct {
	ID        string
	Title     string
	Severity  finding.Severity
	Pattern   *regexp.Regexp
	Validator string
}

// rules is the built-in detection set. Patterns are deliberately tight to keep
// false positives low — andas's promise is signal, not noise.
var rules = []Rule{
	{
		ID:        "github-pat",
		Title:     "GitHub Personal Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		Validator: "github",
	},
	{
		ID:        "github-fine-grained-pat",
		Title:     "GitHub Fine-Grained PAT",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
		Validator: "github",
	},
	{
		ID:        "gitlab-pat",
		Title:     "GitLab Personal Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20}`),
		Validator: "gitlab",
	},
	{
		ID:        "slack-token",
		Title:     "Slack Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,60}`),
		Validator: "slack",
	},
	{
		ID:        "stripe-secret",
		Title:     "Stripe Secret Key",
		Severity:  finding.SevCritical,
		Pattern:   regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
		Validator: "stripe",
	},
	{
		ID:        "aws-access-key",
		Title:     "AWS Access Key ID",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
		Validator: "", // needs the paired secret + signing; not yet validated
	},
	{
		ID:        "google-api-key",
		Title:     "Google API Key",
		Severity:  finding.SevMedium,
		Pattern:   regexp.MustCompile(`AIza[A-Za-z0-9_\-]{35}`),
		Validator: "",
	},
	{
		ID:        "openai-key",
		Title:     "OpenAI API Key",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
		Validator: "",
	},
	{
		ID:        "private-key",
		Title:     "Private Key Block",
		Severity:  finding.SevCritical,
		Pattern:   regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		Validator: "",
	},
}
