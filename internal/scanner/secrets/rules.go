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
		ID:        "anthropic-key",
		Title:     "Anthropic API Key",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`sk-ant-[A-Za-z0-9]{2,}-[A-Za-z0-9_\-]{80,}`),
		Validator: "anthropic",
	},
	{
		ID:        "doppler-token",
		Title:     "Doppler Token (secrets manager)",
		Severity:  finding.SevCritical, // a secrets manager token can read ALL your secrets
		Pattern:   regexp.MustCompile(`dp\.(?:pt|st|sa|scim|audit)\.[A-Za-z0-9]{40,44}`),
		Validator: "doppler",
	},
	{
		ID:       "square-token",
		Title:    "Square Access Token",
		Severity: finding.SevCritical, // payments
		// A leading non-base64 boundary stops it matching a 64-char run inside a
		// base64 blob (e.g. a data: image URL) — a real false positive seen in the
		// wild in swagger-ui CSS.
		Pattern:   regexp.MustCompile(`(?:^|[^A-Za-z0-9/+=_-])EAAA[A-Za-z0-9_\-]{60}`),
		Validator: "square",
	},
	{
		ID:        "hubspot-token",
		Title:     "HubSpot Private App Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`pat-[a-z]{2}\d-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
		Validator: "hubspot",
	},
	{
		ID:        "mailchimp-key",
		Title:     "Mailchimp API Key",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`[0-9a-f]{32}-us\d{1,2}`),
		Validator: "mailchimp",
	},
	{
		ID:        "linear-key",
		Title:     "Linear API Key",
		Severity:  finding.SevMedium,
		Pattern:   regexp.MustCompile(`lin_api_[A-Za-z0-9]{40}`),
		Validator: "linear",
	},
	{
		ID:       "discord-bot-token",
		Title:    "Discord Bot Token",
		Severity: finding.SevHigh,
		// Three base64url parts like a JWT, but the first segment encodes a numeric
		// snowflake id (starts M/N/O), so it can't be confused with a JWT (eyJ…).
		Pattern:   regexp.MustCompile(`[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}`),
		Validator: "discord",
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
		ID:        "figma-token",
		Title:     "Figma Personal Access Token",
		Severity:  finding.SevMedium,
		Pattern:   regexp.MustCompile(`figd_[A-Za-z0-9_-]{40,}`),
		Validator: "figma",
	},
	{
		ID:        "notion-token",
		Title:     "Notion Integration Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`ntn_[A-Za-z0-9]{36,}`),
		Validator: "notion",
	},
	{
		ID:        "airtable-token",
		Title:     "Airtable Personal Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}`),
		Validator: "airtable",
	},
	{
		ID:        "postman-key",
		Title:     "Postman API Key",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`),
		Validator: "postman",
	},
	{
		ID:        "dropbox-token",
		Title:     "Dropbox Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`sl\.[A-Za-z0-9_-]{100,}`),
		Validator: "dropbox",
	},
	{
		ID:        "shopify-token",
		Title:     "Shopify Access Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Validator: "", // needs the shop domain to verify; detection only
	},
	{
		ID:        "pypi-token",
		Title:     "PyPI Upload Token",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`pypi-[A-Za-z0-9_-]{16,}`),
		Validator: "", // no read-only verify endpoint; detection only
	},
	{
		ID:        "connection-string-creds",
		Title:     "Credentials embedded in a connection URL",
		Severity:  finding.SevHigh,
		Pattern:   regexp.MustCompile(`(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|smtp)://[^:@/\s]*:[^@/\s]{3,}@[^\s"'` + "`" + `]+`),
		Validator: "", // the embedded password can't be provider-validated generically
	},
	{
		ID:        "weak-default-password",
		Title:     "Hardcoded weak/default password",
		Severity:  finding.SevMedium,
		Pattern:   regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"](?:admin|administrator|password|passwd|123456|12345678|changeme|root|toor|test|secret|welcome|letmein|default|qwerty|p@ssw0rd)['"]`),
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
