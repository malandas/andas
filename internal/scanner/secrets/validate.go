package secrets

import (
	"fmt"
	"net/http"
	"time"
)

// validate performs a safe, read-only call to the credential's own provider to
// learn whether it is still active. This is the core of naqi: a dead secret is
// noise, a live one is an emergency, and only the provider can tell them apart.
//
// Every check here is non-mutating (it reads identity/account info, never
// writes) and is sent only to the legitimate provider endpoint for that
// credential type.
func validate(kind, secret string, timeoutS int) (live bool, note string) {
	if timeoutS <= 0 {
		timeoutS = 8
	}
	client := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}

	switch kind {
	case "github":
		return checkStatus(client, "GET", "https://api.github.com/user",
			map[string]string{"Authorization": "token " + secret})
	case "gitlab":
		return checkStatus(client, "GET", "https://gitlab.com/api/v4/user",
			map[string]string{"PRIVATE-TOKEN": secret})
	case "slack":
		// auth.test accepts the token as a bearer and only reports identity.
		return checkStatus(client, "POST", "https://slack.com/api/auth.test",
			map[string]string{"Authorization": "Bearer " + secret})
	case "stripe":
		// Stripe uses HTTP basic auth with the key as the username.
		return checkBasic(client, "https://api.stripe.com/v1/account", secret)
	default:
		return false, "no validator"
	}
}

// checkStatus sends a request with the given headers and treats a 2xx as proof
// the credential is live. 401/403 means dead/revoked; anything else is unknown.
func checkStatus(c *http.Client, method, url string, headers map[string]string) (bool, string) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return false, "request build failed"
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return false, "network error: " + err.Error()
	}
	defer resp.Body.Close()
	return interpret(resp.StatusCode)
}

func checkBasic(c *http.Client, url, user string) (bool, string) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "request build failed"
	}
	req.SetBasicAuth(user, "")
	resp, err := c.Do(req)
	if err != nil {
		return false, "network error: " + err.Error()
	}
	defer resp.Body.Close()
	return interpret(resp.StatusCode)
}

func interpret(code int) (bool, string) {
	switch {
	case code >= 200 && code < 300:
		return true, "provider accepted the credential (HTTP 200) — LIVE"
	case code == 401 || code == 403:
		return false, "provider rejected the credential — revoked or dead"
	default:
		return false, fmt.Sprintf("inconclusive (HTTP %d)", code)
	}
}
