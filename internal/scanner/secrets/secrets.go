// Package secrets detects hardcoded credentials and — andas's differentiator —
// verifies whether each one is still live before deciding how loud to be.
package secrets

import (
	"strings"
	"time"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/gitmeta"
	"github.com/malandas/andas/internal/scanner"
)

// Scanner finds secrets and, when enabled, validates them.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "secrets" }

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	files, err := scanner.WalkText(root, opts.IgnorePaths)
	if err != nil {
		return nil, err
	}

	repoAvail := gitmeta.Available(root)
	now := time.Now()
	// exposure fills the "how long has this been leaked?" field from git blame.
	exposure := func(file string, line int) string {
		if !repoAvail {
			return ""
		}
		if t, ok := gitmeta.LineIntroduced(root, file, line); ok {
			return gitmeta.Describe(t, now)
		}
		return ""
	}

	var out []finding.Finding
	for _, f := range files {
		fileText := strings.Join(f.Lines, "\n")
		for lineNo, line := range f.Lines {
			for _, rule := range rules {
				m := rule.Pattern.FindString(line)
				if m == "" {
					continue
				}
				fnd := finding.Finding{
					Kind:     finding.KindSecret,
					RuleID:   rule.ID,
					Title:    rule.Title,
					File:     f.Path,
					Line:     lineNo + 1,
					Match:    finding.Redact(m),
					Severity: rule.Severity,
					Fix:      secretFix(rule.ID),
				}
				switch {
				case !opts.Validate || rule.Validator == "":
					if rule.Validator == "" {
						fnd.Context.Note = "no live validator for this type yet"
					}
				case rule.Validator == "aws":
					// AWS needs the paired secret; look for one in the same file.
					if secret := findAWSSecret(fileText, m); secret != "" {
						applyResult(&fnd.Context, awsValidateSTS(m, secret, opts.TimeoutS))
					} else {
						fnd.Context.Note = "no paired secret key found near it — cannot verify"
					}
				case rule.Validator == "twilio":
					if token := findTwilioToken(fileText, m); token != "" {
						applyResult(&fnd.Context, twilioValidate(m, token, opts.TimeoutS))
					} else {
						fnd.Context.Note = "no paired auth token found near it — cannot verify"
					}
				default:
					applyResult(&fnd.Context, validate(rule.Validator, m, opts.TimeoutS))
				}
				fnd.Context.Exposure = exposure(f.Path, lineNo+1)
				out = append(out, fnd)
			}

			// Entropy pass: catch secret-like values no typed rule matched.
			if opts.Entropy {
				for _, m := range reAssign.FindAllStringSubmatch(line, -1) {
					v := m[2]
					if !isLikelySecret(v) {
						continue
					}
					out = append(out, finding.Finding{
						Kind:     finding.KindSecret,
						RuleID:   genericRuleID,
						Title:    "High-entropy secret-like value",
						File:     f.Path,
						Line:     lineNo + 1,
						Match:    finding.Redact(v),
						Severity: finding.SevMedium,
						Fix:      secretFix(genericRuleID),
						Context: finding.Context{
							Note:     "matched by entropy heuristic — unverified; baseline it if it's a false positive",
							Exposure: exposure(f.Path, lineNo+1),
						},
					})
				}
			}
		}
	}
	return out, nil
}

// genericRuleID marks findings from the entropy heuristic rather than a typed rule.
const genericRuleID = "generic-high-entropy"

// applyResult copies a validation Result (liveness + blast radius) onto a
// finding's context.
func applyResult(c *finding.Context, r Result) {
	c.Validated = true
	c.Live = r.Live
	c.Note = r.Note
	c.Identity = r.Identity
	c.Access = r.Scopes
	c.Privileged = r.Privileged
}
