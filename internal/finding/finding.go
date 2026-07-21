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
	KindCode    Kind = "code"    // a dangerous pattern in the user's own source (SAST)
	KindConfig  Kind = "config"  // an insecure infrastructure/CI configuration (IaC)
	KindLicense Kind = "license" // a dependency whose license carries obligations/risk
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

	// Secrets: the matched value is an obvious template/dummy (REPLACE, <your-key>,
	// the AWS docs EXAMPLE key…), so it is not a real credential — demoted to noise.
	Placeholder bool `json:"placeholder,omitempty"`

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
// Confidence expresses how strongly andas stands behind a finding after it
// tries to refute its own result — the antidote to scanner noise. It is derived
// from the evidence, so it's deterministic and needs no extra state.
type Confidence int

const (
	Tentative Confidence = iota // heuristic-only, or in test code — verify before acting
	Firm                        // a solid detection; no refutation succeeded
	Confirmed                   // proven: a live secret, or user input reaching the sink
)

func (c Confidence) String() string {
	switch c {
	case Confirmed:
		return "confirmed"
	case Firm:
		return "firm"
	default:
		return "tentative"
	}
}

// Confidence runs andas's self-refutation: it downgrades findings that a
// skeptic would challenge (a match in test code, an unverified heuristic, a
// placeholder) and upgrades those it can prove (a live secret, user input that
// provably reaches the sink).
func (f Finding) Confidence() Confidence {
	switch f.Kind {
	case KindSecret:
		switch {
		case f.Context.Placeholder:
			return Tentative // refuted: it's a template value
		case f.Context.Validated && f.Context.Live:
			return Confirmed // proven live against the provider
		case f.RuleID == "generic-high-entropy":
			return Tentative // entropy guess, unverified
		default:
			return Firm
		}
	case KindCode:
		if isTestPath(f.File) {
			return Tentative // refuted as production risk: it's test code
		}
		if f.Context.UserInput {
			return Confirmed // taint proved user input reaches this sink
		}
		return Firm
	case KindVuln:
		if f.Context.Reachable != nil && *f.Context.Reachable {
			return Confirmed
		}
		return Firm
	default:
		return Firm
	}
}

// isTestPath reports whether a file is test/spec code, where a dangerous pattern
// is far less likely to be a real production risk.
func isTestPath(p string) bool {
	// Prepend "/" so a path that starts with the test dir (tests/foo.py) matches
	// the same "/tests/" check as a nested one.
	pl := "/" + strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, s := range []string{"_test.", ".test.", ".spec.", "/test/", "/tests/", "/__tests__/", "/spec/", "/testdata/", "/test_", "test_"} {
		if strings.Contains(pl, s) {
			return true
		}
	}
	return strings.HasSuffix(pl, "tests.cs") || strings.HasSuffix(pl, "test.cs")
}

func (f Finding) RealRisk() Severity {
	switch f.Kind {
	case KindSecret:
		if f.Context.Placeholder {
			return SevInfo // a template/dummy value, not a real credential — noise
		}
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
