package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// AttackPath reads the confirmed findings and narrates how they chain together
// from an attacker's point of view. It never invents risk — every line is
// grounded in a live credential, a reachable vulnerability, or a history leak
// that andas actually verified. Returns nil when there's nothing to chain.
func AttackPath(fs []finding.Finding) []string {
	var liveCount, privileged, reachableVuln int
	provs := map[string]bool{}
	historyLive := false
	var privLines []string

	for _, f := range fs {
		switch {
		case f.Kind == finding.KindSecret && f.Context.Validated && f.Context.Live:
			liveCount++
			provs[providerLabel(f.RuleID)] = true
			if strings.Contains(f.File, "git history") {
				historyLive = true
			}
			if f.Context.Privileged {
				privileged++
				id := f.Context.Identity
				if id == "" {
					id = "the account"
				}
				acc := strings.Join(f.Context.Access, ", ")
				if acc == "" {
					acc = "privileged access"
				}
				privLines = append(privLines, fmt.Sprintf(
					"A live, high-privilege %s (%s) is exposed — an attacker gains %s.",
					providerLabel(f.RuleID), id, acc))
			}
		case f.Kind == finding.KindVuln && f.Context.Reachable != nil && *f.Context.Reachable && f.RealRisk() >= finding.SevHigh:
			reachableVuln++
		}
	}

	if liveCount == 0 && reachableVuln == 0 {
		return nil
	}

	lines := append([]string{}, privLines...)
	if len(provs) >= 2 {
		lines = append(lines, "Multiple live credentials are exposed together ("+
			strings.Join(sortedKeys(provs), ", ")+") — one leaked repo hands an attacker all of them at once.")
	}
	if liveCount > 0 && reachableVuln > 0 {
		lines = append(lines, "A reachable vulnerability alongside a live credential chains a code foothold into account takeover.")
	}
	if historyLive {
		lines = append(lines, "A credential removed from the code is still live in git history — deleting the line never rotated the key.")
	}
	if len(lines) == 0 && liveCount > 0 {
		lines = append(lines, "A live credential is exposed — anyone with read access to this repo can use it right now.")
	}
	return lines
}

// providerLabel maps a rule id to a human provider name for the narrative.
func providerLabel(ruleID string) string {
	for prefix, name := range map[string]string{
		"github": "GitHub", "gitlab": "GitLab", "aws": "AWS", "stripe": "Stripe",
		"slack": "Slack", "npm": "npm", "sendgrid": "SendGrid", "telegram": "Telegram",
		"openai": "OpenAI", "twilio": "Twilio", "google": "Google",
	} {
		if strings.HasPrefix(ruleID, prefix) {
			return name
		}
	}
	return "a service"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
