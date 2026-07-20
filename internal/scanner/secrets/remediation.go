package secrets

// secretFix returns the concrete remediation step for a detected secret type —
// where to revoke/rotate it. A found secret must be treated as compromised even
// if it's later removed from the code, so the advice is always "rotate", never
// "just delete the line".
func secretFix(ruleID string) string {
	switch ruleID {
	case "github-pat", "github-fine-grained-pat":
		return "Revoke the token at https://github.com/settings/tokens, then issue a new one."
	case "gitlab-pat":
		return "Revoke at GitLab → Settings → Access Tokens, then rotate."
	case "slack-token":
		return "Rotate the token in the Slack app config (api.slack.com/apps) and re-deploy."
	case "stripe-secret":
		return "Roll the key immediately at https://dashboard.stripe.com/apikeys."
	case "aws-access-key":
		return "Deactivate the key in IAM → Security credentials, then create a fresh pair."
	case "npm-token":
		return "Revoke at https://www.npmjs.com/settings/~/tokens and mint a new one."
	case "sendgrid-key":
		return "Delete the key in SendGrid → Settings → API Keys and regenerate."
	case "telegram-bot-token":
		return "Use @BotFather → /revoke to reset the bot token."
	case "google-api-key":
		return "Regenerate the key in Google Cloud Console → APIs & Services → Credentials, and add restrictions."
	case "openai-key":
		return "Revoke at https://platform.openai.com/api-keys and rotate."
	case "twilio-account-sid":
		return "Rotate the auth token in the Twilio console (Account → API keys & tokens)."
	case "github-oauth":
		return "Revoke the token in the GitHub OAuth/GitHub App settings and re-issue."
	case "digitalocean-token":
		return "Regenerate the token at https://cloud.digitalocean.com/account/api/tokens."
	case "mailgun-key":
		return "Rotate the key in the Mailgun dashboard (Settings → API Keys)."
	case "private-key":
		return "Treat the private key as compromised: rotate the key pair and re-issue any certs signed by it."
	default:
		return "Rotate this credential and remove it from source; load it from an environment variable instead."
	}
}
