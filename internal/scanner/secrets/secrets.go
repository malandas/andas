// Package secrets detects hardcoded credentials and — naqi's differentiator —
// verifies whether each one is still live before deciding how loud to be.
package secrets

import (
	"github.com/mm-fid/naqi/internal/finding"
	"github.com/mm-fid/naqi/internal/scanner"
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
				if opts.Validate && rule.Validator != "" {
					live, note := validate(rule.Validator, m, opts.TimeoutS)
					fnd.Context.Validated = true
					fnd.Context.Live = live
					fnd.Context.Note = note
				} else if rule.Validator == "" {
					fnd.Context.Note = "no live validator for this type yet"
				}
				out = append(out, fnd)
			}
		}
	}
	return out, nil
}
