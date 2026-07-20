package secrets

import (
	"encoding/json"
	"strings"
)

// This file holds the small, pure parsers that turn a provider's response into
// blast-radius data (identity, scopes, privilege). Kept separate and dependency
// -free so they're trivially unit-testable without any network.

// parseScopeHeader splits GitHub's "X-OAuth-Scopes: repo, gist, admin:org".
func parseScopeHeader(h string) []string {
	var out []string
	for _, s := range strings.Split(h, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// githubPrivileged reports whether a GitHub token's scopes grant dangerous power
// — full repo write, org/enterprise admin, repo deletion, or CI control.
func githubPrivileged(scopes []string) bool {
	for _, s := range scopes {
		switch s {
		case "repo", "delete_repo", "admin:org", "workflow", "admin:enterprise", "write:packages":
			return true
		}
		if strings.HasPrefix(s, "admin:") {
			return true
		}
	}
	return false
}

func hasAdminScope(scopes []string) bool {
	for _, s := range scopes {
		if strings.Contains(strings.ToLower(s), "admin") {
			return true
		}
	}
	return false
}

func containsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}

// jsonString pulls a top-level string (or stringified bool/number) field.
func jsonString(body []byte, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func jsonBool(body []byte, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	var b bool
	return m[key] != nil && json.Unmarshal(m[key], &b) == nil && b
}

// jsonStringSlice pulls a top-level array-of-strings field.
func jsonStringSlice(body []byte, key string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	var out []string
	if raw, ok := m[key]; ok {
		json.Unmarshal(raw, &out)
	}
	return out
}

// awsArn extracts the ARN from an STS GetCallerIdentity XML response.
func awsArn(body []byte) string {
	return between(string(body), "<Arn>", "</Arn>")
}

// awsAccount extracts the account id from the same response.
func awsAccount(body []byte) string {
	return between(string(body), "<Account>", "</Account>")
}

// awsPrivileged flags the most dangerous AWS identities: the account root, or an
// identity whose name signals administrative reach.
func awsPrivileged(arn string) bool {
	low := strings.ToLower(arn)
	return strings.HasSuffix(arn, ":root") || strings.Contains(low, "admin") || strings.Contains(low, "root")
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	i += len(open)
	j := strings.Index(s[i:], close)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}
