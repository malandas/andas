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
		Validator: "aws", // validated by pairing with a nearby secret (see secrets.go)
	},
	{
		ID:        "npm-token",
		Title:     "npm Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Validator: "npm",
	},
	{
		ID:        "sendgrid-key",
		Title:     "SendGrid API Key",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
		Validator: "sendgrid",
	},
	{
		ID:        "telegram-bot-token",
		Title:     "Telegram Bot Token",
		Severity:  finding.SevMedium,
		Pattern:   regexp.MustCompile(`\d{8,10}:[A-Za-z0-9_\-]{35}`),
		Validator: "telegram",
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
		Validator: "openai",
	},
	{
		ID:        "twilio-account-sid",
		Title:     "Twilio Account SID",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`AC[0-9a-fA-F]{32}`),
		Validator: "twilio", // validated by pairing with a nearby auth token
	},
	{
		ID:        "github-oauth",
		Title:     "GitHub OAuth/App Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`gh[ousr]_[A-Za-z0-9]{36}`),
		Validator: "github", // same identity/scopes endpoint as a PAT
	},
	{
		ID:        "digitalocean-token",
		Title:     "DigitalOcean Personal Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		Validator: "digitalocean",
	},
	{
		ID:        "mailgun-key",
		Title:     "Mailgun API Key",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`key-[0-9a-f]{32}`),
		Validator: "mailgun",
	},
	{
		ID:        "private-key",
		Title:     "Private Key Block",
		Severity:  finding.SevCritical,
		Pattern:   regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		Validator: "",
	},
}
