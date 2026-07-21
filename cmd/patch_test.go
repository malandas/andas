package cmd

import (
	"strings"
	"testing"
)

func TestSuggestPatch(t *testing.T) {
	cases := []struct{ rule, in, wantContains string }{
		{"cs-open-redirect", "return Redirect(url);", "LocalRedirect(url)"},
		{"tls-verify-disabled", "requests.get(u, verify=False)", "verify=True"},
		{"tls-verify-disabled", "new https.Agent({ rejectUnauthorized: false })", "rejectUnauthorized: true"},
		{"weak-hash", "h = hashlib.md5(x)", "hashlib.sha256("},
		{"cs-cookie-insecure", "opt.HttpOnly = false;", "HttpOnly = true"},
		{"cs-jwt-validation-disabled", "p.ValidateIssuer = false;", "ValidateIssuer = true"},
		{"ruby-insecure-deser", "YAML.load(input)", "YAML.safe_load("},
	}
	for _, c := range cases {
		got, ok := suggestPatch(c.rule, c.in)
		if !ok {
			t.Errorf("%s: no patch for %q", c.rule, c.in)
			continue
		}
		if !strings.Contains(got, c.wantContains) {
			t.Errorf("%s: patch %q missing %q", c.rule, got, c.wantContains)
		}
	}
	// A rule with no mechanical fix returns ok=false.
	if _, ok := suggestPatch("cs-sql-raw", `db.ExecuteSqlRaw($"... {id}")`); ok {
		t.Error("SQLi has no safe one-line patch; should return ok=false")
	}
	// LocalRedirect must not be double-wrapped.
	if got, _ := suggestPatch("cs-open-redirect", "return LocalRedirect(url);"); strings.Contains(got, "LocalLocalRedirect") {
		t.Error("must not double-rewrite an already-safe LocalRedirect")
	}
}
