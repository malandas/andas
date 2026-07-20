// Package license classifies dependency licenses and flags ones that carry
// obligations a typical closed-source product can't meet — strong copyleft
// (GPL/AGPL), or a missing/unknown license (which legally means "no rights
// granted"). It fits andas's real-risk philosophy: a permissive MIT dep is
// noise, a live AGPL obligation in a proprietary app is the thing to surface.
package license

import (
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// Risk is how much obligation/danger a license carries for a closed product.
type Risk int

const (
	Permissive Risk = iota // MIT, BSD, Apache — no real obligation
	Weak                   // LGPL, MPL, EPL — file-level copyleft
	Strong                 // GPL, AGPL — viral; big obligation for proprietary use
	Unknown                // unrecognised or missing — legally "no rights granted"
)

// Classify maps a raw SPDX-ish license string to a Risk. It is deliberately
// conservative: anything it doesn't recognise is Unknown, not Permissive.
func Classify(raw string) Risk {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" || s == "UNLICENSED" || s == "SEE LICENSE IN LICENSE" {
		return Unknown
	}
	switch {
	case strings.Contains(s, "AGPL"):
		return Strong
	case strings.Contains(s, "GPL") && !strings.Contains(s, "LGPL"):
		return Strong
	case strings.Contains(s, "LGPL"), strings.Contains(s, "MPL"),
		strings.Contains(s, "EPL"), strings.Contains(s, "CDDL"):
		return Weak
	case containsAny(s, "MIT", "BSD", "APACHE", "ISC", "UNLICENSE", "0BSD", "ZLIB", "WTFPL", "CC0", "PYTHON", "PSF"):
		return Permissive
	default:
		return Unknown
	}
}

// Severity turns a license Risk into an andas severity, given whether the user
// declared their project proprietary (the default assumption). Copyleft only
// matters against a closed product; for an OSS project it's informational.
func (r Risk) Severity(proprietary bool) finding.Severity {
	switch r {
	case Strong:
		if proprietary {
			return finding.SevHigh
		}
		return finding.SevLow
	case Weak:
		if proprietary {
			return finding.SevMedium
		}
		return finding.SevLow
	case Unknown:
		return finding.SevMedium // a missing license is a real legal risk either way
	default:
		return finding.SevInfo
	}
}

// RuleID is a stable identifier for baseline/config filtering.
func (r Risk) RuleID() string {
	switch r {
	case Strong:
		return "license-strong-copyleft"
	case Weak:
		return "license-weak-copyleft"
	case Unknown:
		return "license-unknown"
	default:
		return "license-permissive"
	}
}

func (r Risk) String() string {
	switch r {
	case Strong:
		return "strong copyleft"
	case Weak:
		return "weak copyleft"
	case Unknown:
		return "unknown/missing license"
	default:
		return "permissive"
	}
}

// Note explains why a license was flagged, for the finding's context line.
func (r Risk) Note(spdx string, proprietary bool) string {
	switch r {
	case Strong:
		if proprietary {
			return spdx + " is strong copyleft — distributing a proprietary product linked against it can require releasing your source"
		}
		return spdx + " is strong copyleft (informational for an open-source project)"
	case Weak:
		return spdx + " is weak/file-level copyleft — review your linking and distribution model"
	case Unknown:
		return "no recognised license — legally this grants you no rights to use it; confirm before shipping"
	default:
		return spdx + " — permissive"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
