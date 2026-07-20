// Package finding defines the unified result model shared by every scanner.
//
// The whole point of andas is the distinction between two numbers:
//   - Severity: the theoretical severity of an issue (e.g. a CVSS score, or
//     "this looks like an AWS key"). Every scanner in the world reports this.
//   - RealRisk: the contextual risk *for this project specifically*, after we
//     ask the expensive question — is this secret actually live? is this
//     vulnerable function actually reachable? That question is andas's job.
package finding

import "strings"

// Kind is the category of a finding.
type Kind string

const (
	KindSecret Kind = "secret"
	KindVuln   Kind = "vulnerability"
	KindCode   Kind = "code"   // a dangerous pattern in the user's own source (SAST)
	KindConfig Kind = "config" // an insecure infrastructure/CI configuration (IaC)
)

// Severity is an ordered risk level.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Context holds the evidence andas gathers to turn a raw detection into a
// real-risk judgement. Fields are populated per-Kind.
type Context struct {
	// Secrets: live-validation evidence.
	Validated bool   `json:"validated"` // did we attempt to verify it?
	Live      bool   `json:"live"`      // is the secret confirmed active?
	Note      string `json:"note,omitempty"`

	// Secrets: blast radius — what a live credential can actually reach. This is
	// the difference between "a live token" and "a live admin token".
	Identity   string   `json:"identity,omitempty"`   // who/what the credential authenticates as
	Access     []string `json:"access,omitempty"`     // scopes/capabilities it grants
	Privileged bool     `json:"privileged,omitempty"` // elevated/admin-level access

	// Secrets: how long the secret has been exposed (from git blame / history).
	Exposure string `json:"exposure,omitempty"`

	// Vulnerabilities: reachability evidence (populated by a later module).
	// nil = not analysed, true = the vulnerable code path is callable.
	Reachable *bool `json:"reachable,omitempty"`

	// Symbols the app actually uses from a vulnerable package (e.g. the lodash
	// functions it imports/calls). Evidence for triage — we deliberately do NOT
	// downgrade on this, since mapping an advisory to exact functions is
	// unreliable and a false "safe" is worse than a false alarm.
	Symbols []string `json:"symbols,omitempty"`

	// Code (SAST): the CWE id, and whether user-controlled input appears on the
	// same line — a dangerous sink fed by user input is far likelier to be real.
	CWE       string `json:"cwe,omitempty"`
	UserInput bool   `json:"user_input,omitempty"`
}

// Finding is a single issue surfaced by a scanner.
type Finding struct {
	Kind     Kind     `json:"kind"`
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Match    string   `json:"match"` // already redacted, safe to print
	Severity Severity `json:"severity"`
	Fix      string   `json:"fix,omitempty"` // concrete remediation step
	Context  Context  `json:"context"`
}

// RealRisk is the contextual score andas actually ranks and reports on.
//
// The rule is simple and is the heart of the product: proven-exploitable
// issues get promoted, proven-harmless ones get demoted into the noise, and
// everything we couldn't verify keeps its theoretical severity.
func (f Finding) RealRisk() Severity {
	switch f.Kind {
	case KindSecret:
		if !f.Context.Validated {
			return f.Severity // we didn't check; report as-is
		}
		if f.Context.Live {
			return SevCritical // a working credential is always critical
		}
		return SevInfo // confirmed dead — this is the noise we exist to remove

	case KindVuln:
		if f.Context.Reachable == nil {
			return f.Severity
		}
		if *f.Context.Reachable {
			return f.Severity // reachable: keep full weight
		}
		return SevLow // unreachable: technically present, practically noise

	default:
		return f.Severity
	}
}

// Redact keeps a secret printable without leaking it: first 4 and last 2
// characters, the middle replaced by a fixed mask.
func Redact(secret string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", 6) + secret[len(secret)-2:]
}
