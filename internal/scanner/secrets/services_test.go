package secrets

import "testing"

func TestService(t *testing.T) {
	cases := map[string]string{
		"stripe-secret":      "Stripe",
		"github-pat":         "GitHub",
		"aws-access-key":     "AWS",
		"twilio-account-sid": "Twilio",
	}
	for rule, want := range cases {
		if name, host := Service(rule); name != want || host == "" {
			t.Errorf("Service(%q) = (%q,%q), want name %q with a host", rule, name, host, want)
		}
	}
	if name, _ := Service("nonexistent-rule"); name != "" {
		t.Errorf("unknown rule should map to empty, got %q", name)
	}
}
