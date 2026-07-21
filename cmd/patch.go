package cmd

import "regexp"

// A suggested fix is a mechanical, safe line rewrite andas is confident about —
// the kind a reviewer would type by hand. Findings that need real restructuring
// (parameterising a query) get advice, not a patch; only unambiguous one-liners
// are offered here so an applied suggestion is always correct.
type transform struct {
	re   *regexp.Regexp
	repl string
}

var patchTransforms = map[string][]transform{
	// Open redirect → LocalRedirect (rejects off-site targets).
	"cs-open-redirect": {
		{regexp.MustCompile(`\bRedirect\s*\(`), "LocalRedirect("},
	},
	// TLS verification back on.
	"tls-verify-disabled": {
		{regexp.MustCompile(`verify\s*=\s*False`), "verify=True"},
		{regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`), "InsecureSkipVerify: false"},
		{regexp.MustCompile(`rejectUnauthorized\s*:\s*false`), "rejectUnauthorized: true"},
		{regexp.MustCompile(`check_hostname\s*=\s*False`), "check_hostname = True"},
	},
	// Cookie hardening.
	"cookie-insecure": {
		{regexp.MustCompile(`httpOnly\s*:\s*false`), "httpOnly: true"},
		{regexp.MustCompile(`secure\s*:\s*false`), "secure: true"},
	},
	"cs-cookie-insecure": {
		{regexp.MustCompile(`HttpOnly\s*=\s*false`), "HttpOnly = true"},
		{regexp.MustCompile(`Secure\s*=\s*false`), "Secure = true"},
	},
	// Re-enable JWT/OIDC validation flags.
	"cs-jwt-validation-disabled": {
		{regexp.MustCompile(`(ValidateIssuer|ValidateAudience|ValidateLifetime|RequireExpirationTime|ValidateIssuerSigningKey|RequireSignedTokens|RequireHttpsMetadata)\s*=\s*false`), "$1 = true"},
	},
	// Safe YAML loader.
	"ruby-insecure-deser": {
		{regexp.MustCompile(`YAML\.load\s*\(`), "YAML.safe_load("},
		{regexp.MustCompile(`Psych\.load\s*\(`), "Psych.safe_load("},
	},
	// Weak hash → SHA-256.
	"weak-hash": {
		{regexp.MustCompile(`hashlib\.md5\s*\(`), "hashlib.sha256("},
		{regexp.MustCompile(`hashlib\.sha1\s*\(`), "hashlib.sha256("},
		{regexp.MustCompile(`MD5\.Create\s*\(`), "SHA256.Create("},
		{regexp.MustCompile(`SHA1\.Create\s*\(`), "SHA256.Create("},
	},
	// Debug mode off.
	"cs-dev-exception": {
		{regexp.MustCompile(`(?i)UseDeveloperExceptionPage\s*\(\s*\)`), "UseExceptionHandler(\"/error\")"},
	},
}

// suggestPatch returns a fixed version of line for a mechanical finding, or
// ok=false when no safe automatic rewrite applies.
func suggestPatch(ruleID, line string) (string, bool) {
	for _, t := range patchTransforms[ruleID] {
		if t.re.MatchString(line) {
			if nl := t.re.ReplaceAllString(line, t.repl); nl != line {
				return nl, true
			}
		}
	}
	return "", false
}
