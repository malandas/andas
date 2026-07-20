package secrets

import (
	"io"
	"net/http"
	"regexp"
	"time"
)

// Like AWS, a Twilio Account SID can't be validated alone — it's paired with a
// 32-hex auth token. When we find a SID we look for its token nearby and prove
// the pair with a read-only account fetch.

var reTwilioToken = regexp.MustCompile(`[0-9a-fA-F]{32}`)

// findTwilioToken returns the first 32-hex auth-token candidate in text that
// isn't the SID's own hex tail.
func findTwilioToken(text, sid string) string {
	tail := ""
	if len(sid) > 2 {
		tail = sid[2:] // the SID minus its "AC" prefix is also 32 hex
	}
	for _, cand := range reTwilioToken.FindAllString(text, -1) {
		if cand != tail {
			return cand
		}
	}
	return ""
}

// twilioValidate confirms a SID+token pair via a read-only account read.
func twilioValidate(sid, token string, timeoutS int) Result {
	if timeoutS <= 0 {
		timeoutS = 8
	}
	c := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}
	req, err := http.NewRequest("GET",
		"https://api.twilio.com/2010-04-01/Accounts/"+sid+".json", nil)
	if err != nil {
		return Result{Note: "request build failed"}
	}
	req.SetBasicAuth(sid, token)
	resp, err := c.Do(req)
	if err != nil {
		return Result{Note: "network error: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Result{
			Live:       true,
			Note:       "Twilio accepted the SID + token — LIVE",
			Identity:   jsonString(body, "friendly_name"),
			Scopes:     []string{"send SMS/voice (billable)"},
			Privileged: true,
		}
	case resp.StatusCode == 401:
		return Result{Note: "Twilio rejected the pair — invalid or unpaired"}
	default:
		return Result{Note: "inconclusive Twilio response"}
	}
}
