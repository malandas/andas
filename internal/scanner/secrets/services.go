package secrets

// Service maps a secret rule to the service it unlocks and that service's API
// host. For an authorised assessment this turns "a secret was found" into "this
// credential opens <service> at <host>" — the map a tester actually works from.
func Service(ruleID string) (name, host string) {
	switch ruleID {
	case "github-pat", "github-fine-grained-pat", "github-oauth":
		return "GitHub", "api.github.com"
	case "gitlab-pat":
		return "GitLab", "gitlab.com/api"
	case "slack-token":
		return "Slack", "slack.com/api"
	case "stripe-secret":
		return "Stripe", "api.stripe.com"
	case "aws-access-key":
		return "AWS", "sts.amazonaws.com"
	case "twilio-account-sid":
		return "Twilio", "api.twilio.com"
	case "npm-token":
		return "npm registry", "registry.npmjs.org"
	case "sendgrid-key":
		return "SendGrid", "api.sendgrid.com"
	case "telegram-bot-token":
		return "Telegram Bot", "api.telegram.org"
	case "openai-key":
		return "OpenAI", "api.openai.com"
	case "digitalocean-token":
		return "DigitalOcean", "api.digitalocean.com"
	case "mailgun-key":
		return "Mailgun", "api.mailgun.net"
	case "figma-token":
		return "Figma", "api.figma.com"
	case "notion-token":
		return "Notion", "api.notion.com"
	case "airtable-token":
		return "Airtable", "api.airtable.com"
	case "postman-key":
		return "Postman", "api.getpostman.com"
	case "dropbox-token":
		return "Dropbox", "api.dropboxapi.com"
	case "google-api-key":
		return "Google API", "googleapis.com"
	case "shopify-token":
		return "Shopify", "myshopify.com/admin"
	case "pypi-token":
		return "PyPI", "upload.pypi.org"
	case "private-key":
		return "SSH/TLS private key", ""
	default:
		return "", ""
	}
}
