package secrets

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Result is the outcome of validating a secret against its provider. Beyond
// live/dead, it captures the credential's *blast radius* — who it is and what it
// can do — because a live read-only token and a live admin token are worlds
// apart in real risk. This is andas's edge: we already hold the provider on the
// line, so we ask it what the key can actually reach.
type Result struct {
	Live       bool
	Note       string
	Identity   string   // who/what the credential is (user, account, ARN, team, bot)
	Scopes     []string // capabilities/permissions it carries
	Privileged bool     // elevated/admin-level access — the scary kind
}

// validate performs a safe, read-only call to the credential's own provider and,
// when it's live, reads back its identity and permissions. Every request is
// non-mutating and goes only to that credential type's legitimate endpoint.
func validate(kind, secret string, timeoutS int) Result {
	if timeoutS <= 0 {
		timeoutS = 8
	}
	c := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}

	switch kind {
	case "github":
		return validateGitHub(c, secret)
	case "gitlab":
		return validateGitLab(c, secret)
	case "slack":
		return validateSlack(c, secret)
	case "stripe":
		return validateStripe(c, secret)
	case "npm":
		return validateNpm(c, secret)
	case "sendgrid":
		return validateSendGrid(c, secret)
	case "telegram":
		return validateTelegram(c, secret)
	case "openai":
		return validateOpenAI(c, secret)
	case "digitalocean":
		return validateDigitalOcean(c, secret)
	case "mailgun":
		return validateMailgun(c, secret)
	case "figma":
		return validateFigma(c, secret)
	case "notion":
		return validateNotion(c, secret)
	case "airtable":
		return validateAirtable(c, secret)
	default:
		return Result{Note: "no validator"}
	}
}

func validateFigma(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://api.figma.com/v1/me",
		map[string]string{"X-Figma-Token": secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "email")
	r.Scopes = []string{"read/write your Figma files"}
	return r
}

func validateNotion(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://api.notion.com/v1/users/me",
		map[string]string{"Authorization": "Bearer " + secret, "Notion-Version": "2022-06-28"})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "name")
	r.Scopes = []string{"access the connected Notion workspace"}
	return r
}

func validateAirtable(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://api.airtable.com/v0/meta/whoami",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "id")
	r.Scopes = []string{"read/write your Airtable bases"}
	return r
}

func validateDigitalOcean(c *http.Client, secret string) Result {
	code, _, _, err := doReq(c, "GET", "https://api.digitalocean.com/v2/account",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Scopes = []string{"full account access"}
	r.Privileged = true // DO tokens manage droplets, DNS, billing
	return r
}

func validateMailgun(c *http.Client, secret string) Result {
	// Mailgun uses HTTP basic auth with username "api".
	req, _ := http.NewRequest("GET", "https://api.mailgun.net/v3/domains", nil)
	req.SetBasicAuth("api", secret)
	resp, err := c.Do(req)
	if err != nil {
		return Result{Note: "network error: " + err.Error()}
	}
	defer resp.Body.Close()
	r, ok := classify(resp.StatusCode, nil)
	if !ok {
		return r
	}
	r.Scopes = []string{"send email"}
	r.Privileged = true
	return r
}

func validateOpenAI(c *http.Client, secret string) Result {
	code, _, _, err := doReq(c, "GET", "https://api.openai.com/v1/models",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Scopes = []string{"full API access (billable)"}
	r.Privileged = true // a live OpenAI key spends money
	return r
}

// doReq issues a request and returns the status, headers, and (capped) body.
func doReq(c *http.Client, method, url string, headers map[string]string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, body, nil
}

// deadOrInconclusive maps a non-2xx status to a Result; ok reports 2xx.
func classify(code int, err error) (r Result, ok bool) {
	switch {
	case err != nil:
		return Result{Note: "network error: " + err.Error()}, false
	case code >= 200 && code < 300:
		return Result{Live: true, Note: "provider accepted the credential — LIVE"}, true
	case code == 401 || code == 403:
		return Result{Note: "provider rejected the credential — revoked or dead"}, false
	default:
		return Result{Note: fmt.Sprintf("inconclusive (HTTP %d)", code)}, false
	}
}

func validateGitHub(c *http.Client, secret string) Result {
	code, hdr, body, err := doReq(c, "GET", "https://api.github.com/user",
		map[string]string{"Authorization": "token " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "login")
	r.Scopes = parseScopeHeader(hdr.Get("X-OAuth-Scopes"))
	r.Privileged = githubPrivileged(r.Scopes)
	return r
}

func validateGitLab(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://gitlab.com/api/v4/user",
		map[string]string{"PRIVATE-TOKEN": secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "username")
	// A second read-only call surfaces the token's scopes.
	if _, _, tb, err := doReq(c, "GET", "https://gitlab.com/api/v4/personal_access_tokens/self",
		map[string]string{"PRIVATE-TOKEN": secret}); err == nil {
		r.Scopes = jsonStringSlice(tb, "scopes")
		r.Privileged = containsAny(r.Scopes, "api", "sudo", "write_repository")
	}
	return r
}

func validateSlack(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "POST", "https://slack.com/api/auth.test",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	// Slack returns 200 even for a bad token; the body's "ok" is the real signal.
	if jsonString(body, "ok") != "true" && !jsonBool(body, "ok") {
		return Result{Note: "provider rejected the credential — revoked or dead"}
	}
	team, user := jsonString(body, "team"), jsonString(body, "user")
	r.Identity = strings.TrimSpace(team + " / " + user)
	return r
}

func validateStripe(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://api.stripe.com/v1/account",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "id")
	// sk_live_ is an unrestricted secret key — full account access, incl. charges.
	r.Scopes = []string{"full account access"}
	r.Privileged = true
	return r
}

func validateNpm(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://registry.npmjs.org/-/whoami",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Identity = jsonString(body, "username")
	r.Scopes = []string{"publish as " + r.Identity}
	r.Privileged = true // a live npm token can publish packages — supply-chain risk
	return r
}

func validateSendGrid(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://api.sendgrid.com/v3/scopes",
		map[string]string{"Authorization": "Bearer " + secret})
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	r.Scopes = jsonStringSlice(body, "scopes")
	r.Privileged = containsAny(r.Scopes, "mail.send") || hasAdminScope(r.Scopes)
	return r
}

func validateTelegram(c *http.Client, secret string) Result {
	code, _, body, err := doReq(c, "GET", "https://api.telegram.org/bot"+secret+"/getMe", nil)
	r, ok := classify(code, err)
	if !ok {
		return r
	}
	if u := jsonString(body, "username"); u != "" {
		r.Identity = "@" + u
	}
	return r
}
