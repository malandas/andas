// Package report renders findings for humans and machines. Everything is
// ordered by RealRisk, because that ordering is the value andas adds.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// ANSI colours, disabled automatically when NoColor is set.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cGray   = "\033[90m"
)

func color(c, s string, on bool) string {
	if !on {
		return s
	}
	return c + s + cReset
}

func sevColor(s finding.Severity) string {
	switch s {
	case finding.SevCritical, finding.SevHigh:
		return cRed
	case finding.SevMedium:
		return cYellow
	case finding.SevLow:
		return cBlue
	default:
		return cGray
	}
}

// row pairs a finding with its computed real risk so we sort once.
type row struct {
	f    finding.Finding
	risk finding.Severity
}

func rank(findings []finding.Finding) []row {
	rows := make([]row, len(findings))
	for i, f := range findings {
		rows[i] = row{f: f, risk: f.RealRisk()}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].risk != rows[j].risk {
			return rows[i].risk > rows[j].risk // highest real risk first
		}
		// Within a risk level, a high-privilege live credential outranks the rest
		// — same severity, far bigger blast radius.
		return rows[i].f.Context.Privileged && !rows[j].f.Context.Privileged
	})
	return rows
}

// Text writes the human-readable report. useColor toggles ANSI styling.
func Text(w io.Writer, findings []finding.Finding, useColor bool) {
	rows := rank(findings)

	var real, noise int
	for _, r := range rows {
		if r.risk >= finding.SevMedium {
			real++
		} else {
			noise++
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, color(cBold, "  andas — real-risk report", useColor))
	fmt.Fprintln(w, color(cGray, "  ─────────────────────────", useColor))

	if len(rows) == 0 {
		fmt.Fprintln(w, color(cGray, "  no findings. clean scan.", useColor))
		fmt.Fprintln(w)
		return
	}

	for _, r := range rows {
		f := r.f
		sev := color(sevColor(r.risk), fmt.Sprintf("%-8s", r.risk.String()), useColor)
		locStr := f.File
		if f.Line > 0 {
			locStr = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		loc := color(cDim, locStr, useColor)
		fmt.Fprintf(w, "  %s %s\n", sev, color(cBold, f.Title, useColor))
		fmt.Fprintf(w, "           %s  %s\n", loc, color(cGray, f.Match, useColor))

		// Show the context line — this is *why* the risk was up- or downgraded.
		switch f.Kind {
		case finding.KindSecret:
			switch {
			case f.Context.Validated && f.Context.Live:
				fmt.Fprintf(w, "           %s\n", color(cRed, "▲ VERIFIED LIVE — rotate this credential now", useColor))
				if f.Context.Identity != "" {
					fmt.Fprintf(w, "           %s\n", color(cGray, "identity: "+f.Context.Identity, useColor))
				}
				if len(f.Context.Access) > 0 {
					fmt.Fprintf(w, "           %s\n", color(cYellow, "🔓 can access: "+strings.Join(f.Context.Access, ", "), useColor))
				}
				if f.Context.Privileged {
					fmt.Fprintf(w, "           %s\n", color(cRed, "⚠ HIGH-PRIVILEGE credential — maximum blast radius", useColor))
				}
			case f.Context.Validated && !f.Context.Live:
				fmt.Fprintf(w, "           %s\n", color(cGray, "▼ verified dead — demoted out of the noise", useColor))
			case f.Context.Note != "":
				fmt.Fprintf(w, "           %s\n", color(cGray, "• "+f.Context.Note, useColor))
			}
			if f.Context.Exposure != "" {
				fmt.Fprintf(w, "           %s\n", color(cYellow, "⏱ "+f.Context.Exposure, useColor))
			}
		case finding.KindVuln:
			if f.Context.Reachable != nil && *f.Context.Reachable {
				fmt.Fprintf(w, "           %s\n", color(cRed, "▲ "+f.Context.Note, useColor))
				if len(f.Context.Symbols) > 0 {
					used := strings.Join(f.Context.Symbols, ", ")
					fmt.Fprintf(w, "           %s\n", color(cYellow, "↳ your code uses: "+used, useColor))
				}
			} else {
				fmt.Fprintf(w, "           %s\n", color(cGray, "▼ "+f.Context.Note+" — demoted", useColor))
			}
		}

		// Remediation, shown only where it matters — on real risks.
		if f.Fix != "" && r.risk >= finding.SevMedium {
			fmt.Fprintf(w, "           %s\n", color(cGreen, "→ fix: "+f.Fix, useColor))
		}
		fmt.Fprintln(w)
	}

	if ap := AttackPath(findings); len(ap) > 0 {
		fmt.Fprintln(w, color(cRed, "  ⚔ attack path", useColor))
		for _, line := range ap {
			fmt.Fprintf(w, "     %s\n", color(cGray, "• "+line, useColor))
		}
		fmt.Fprintln(w)
	}

	summary := fmt.Sprintf("  %d real risk(s), %d demoted to noise, %d total",
		real, noise, len(rows))
	fmt.Fprintln(w, color(cBold, summary, useColor))
	fmt.Fprintln(w)
}

// JSON writes the machine-readable report, each finding annotated with its
// real_risk so CI pipelines can gate on it.
func JSON(w io.Writer, findings []finding.Finding) error {
	type out struct {
		finding.Finding
		RealRisk string `json:"real_risk"`
	}
	rows := rank(findings)
	items := make([]out, len(rows))
	for i, r := range rows {
		items[i] = out{Finding: r.f, RealRisk: r.risk.String()}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}

// HighestRisk returns the top real-risk level present, for exit-code logic.
func HighestRisk(findings []finding.Finding) finding.Severity {
	max := finding.SevInfo
	for _, f := range findings {
		if r := f.RealRisk(); r > max {
			max = r
		}
	}
	return max
}
