// Package secrets detects hardcoded credentials and — andas's differentiator —
// verifies whether each one is still live before deciding how loud to be.
package secrets

import (
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
)

// Scanner finds secrets and, when enabled, validates them.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "secrets" }

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	files, err := scanner.WalkText(root)
	if err != nil {
		return nil, err
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
				}
				switch {
				case !opts.Validate || rule.Validator == "":
					if rule.Validator == "" {
						fnd.Context.Note = "no live validator for this type yet"
					}
				case rule.Validator == "aws":
					// AWS needs the paired secret; look for one in the same file.
					if secret := findAWSSecret(fileText, m); secret != "" {
						live, note := awsValidateSTS(m, secret, opts.TimeoutS)
						fnd.Context.Validated = true
						fnd.Context.Live = live
						fnd.Context.Note = note
					} else {
						fnd.Context.Note = "no paired secret key found near it — cannot verify"
					}
				default:
					live, note := validate(rule.Validator, m, opts.TimeoutS)
					fnd.Context.Validated = true
					fnd.Context.Live = live
					fnd.Context.Note = note
				}
				out = append(out, fnd)
			}
		}
	}
	return out, nil
}
