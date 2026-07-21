package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner/surface"
)

// --- terminal (text) report -----------------------------------------------

func auditText(w io.Writer, r auditResult, color bool) {
	p := painter(color)
	fmt.Fprintln(w)
	auditHeader(w, r, p)
	auditBadge(w, r, p)
	auditFindings(w, r, p)
	auditSurface(w, r, p)
	auditCandidates(w, r, p)
	auditChains(w, r, p)
	auditPriorities(w, r, p)
	auditFooter(w, r, p)
}

// painter returns a colouring function; a no-op when colour is off.
type paint func(code, s string) string

func painter(color bool) paint {
	return func(code, s string) string {
		if !color {
			return s
		}
		return code + s + "\033[0m"
	}
}

const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cDim   = "\033[2m"
	cRed   = "\033[31m"
	cGrn   = "\033[32m"
	cYel   = "\033[33m"
	cBlue  = "\033[34m"
	cCyan  = "\033[36m"
	cGray  = "\033[90m"
	cOrng  = "\033[38;5;208m"
)

func rule(w io.Writer, p paint, title string) {
	line := "── " + title + " " + strings.Repeat("─", max(3, 48-len(title)))
	fmt.Fprintln(w, "  "+p(cGray, line))
}

func auditHeader(w io.Writer, r auditResult, p paint) {
	fmt.Fprintln(w, "  "+p(cBold+cCyan, "andas")+p(cDim, " · security audit"))
	fmt.Fprintln(w, "  "+p(cGray, "target: "+r.Root+"   ·   "+dur(r.Elapsed)+"   ·   authorised assessment only"))
	fmt.Fprintln(w)
}

// auditBadge draws the letter-grade badge next to the score and one-line verdict.
func auditBadge(w io.Writer, r auditResult, p paint) {
	gc := gradeColor(r.Grade)
	badge := fmt.Sprintf("  %s  ", r.Grade)
	top := "╭" + strings.Repeat("─", len(badge)) + "╮"
	mid := "│" + badge + "│"
	bot := "╰" + strings.Repeat("─", len(badge)) + "╯"

	fmt.Fprintln(w, "    "+p(gc, top))
	fmt.Fprintf(w, "    %s   %s\n", p(gc+cBold, mid), p(cBold, fmt.Sprintf("security posture: %d/100", r.Score)))
	fmt.Fprintf(w, "    %s   %s\n", p(gc, bot), p(cDim, gradeVerdict(r.Grade)))
	fmt.Fprintln(w)
}

func auditFindings(w io.Writer, r auditResult, p paint) {
	rule(w, p, "REAL-RISK FINDINGS")
	c := r.Counts
	fmt.Fprintf(w, "    %s   %s   %s   %s\n",
		tally(p, cRed+cBold, "CRIT", c["CRITICAL"]),
		tally(p, cRed, "HIGH", c["HIGH"]),
		tally(p, cYel, "MED", c["MEDIUM"]),
		tally(p, cGray, "LOW", c["LOW"]),
	)
	// Show the top real-risk findings (most severe first).
	shown := topFindings(r.Findings, 6)
	if len(shown) == 0 {
		fmt.Fprintln(w, "    "+p(cGrn, "no real-risk findings — clean."))
	}
	for _, f := range shown {
		rr := f.RealRisk()
		fmt.Fprintf(w, "    %s  %s\n", p(riskColor(rr)+cBold, pad(rr.String(), 8)), p(cBold, f.Title))
		fmt.Fprintf(w, "              %s\n", p(cGray, f.File+":"+itoa(f.Line)))
	}
	if extra := countReal(r.Findings) - len(shown); extra > 0 {
		fmt.Fprintf(w, "    %s\n", p(cDim, fmt.Sprintf("… and %d more (run `andas scan` for the full list)", extra)))
	}
	fmt.Fprintln(w)
}

func auditSurface(w io.Writer, r auditResult, p paint) {
	rule(w, p, "ATTACK SURFACE")
	fmt.Fprintf(w, "    %s endpoints   ·   %s no visible auth   ·   %s reach a sink\n",
		p(cBold, itoa(r.Endpoints)), p(authColor(r.NoAuth), itoa(r.NoAuth)), p(riskWhen(r.Exploitable), itoa(r.Exploitable)))
	if r.NoAuth > 0 {
		var names []string
		for _, rt := range r.Routes {
			if !rt.Auth {
				names = append(names, rt.Method+" "+rt.Path)
			}
			if len(names) == 6 {
				names = append(names, "…")
				break
			}
		}
		fmt.Fprintf(w, "    %s %s\n", p(cGray, "unauth:"), p(cDim, strings.Join(names, ", ")))
	}
	fmt.Fprintln(w)
}

func auditCandidates(w io.Writer, r auditResult, p paint) {
	rule(w, p, "EXPLOIT CANDIDATES")
	if len(r.Candidates) == 0 {
		fmt.Fprintln(w, "    "+p(cGrn, "none — no endpoint handler reaches a detected sink."))
		fmt.Fprintln(w)
		return
	}
	for i, t := range r.Candidates {
		if i == 4 {
			fmt.Fprintf(w, "    %s\n", p(cDim, fmt.Sprintf("… and %d more (run `andas pentest`)", len(r.Candidates)-4)))
			break
		}
		tags := ""
		if !t.route.Auth {
			tags += p(cRed, " [NO-AUTH]")
		}
		tags += p(cOrng, " ["+externalVerdict(t)+"]")
		fmt.Fprintf(w, "    %s %-26s%s\n", p(cBold, pad(t.route.Method, 6)), t.route.Path, tags)
		if len(t.sinks) > 0 {
			s := t.sinks[0]
			fmt.Fprintf(w, "         %s %s %s\n", p(cGray, "→ reaches"), s.Title, p(cGray, "("+s.Context.CWE+")"))
		}
	}
	fmt.Fprintln(w)
}

func auditChains(w io.Writer, r auditResult, p paint) {
	if len(r.Chains) == 0 {
		return
	}
	rule(w, p, "ATTACK CHAINS")
	for _, c := range r.Chains {
		fmt.Fprintf(w, "    %s %s\n", p(cRed, "▸"), c)
	}
	fmt.Fprintln(w)
}

// auditPriorities is the "what to fix first" list — the single most useful
// output: the highest-leverage actions, ranked, with the concrete fix.
func auditPriorities(w io.Writer, r auditResult, p paint) {
	rule(w, p, "TOP PRIORITIES")
	items := prioritise(r)
	if len(items) == 0 {
		fmt.Fprintln(w, "    "+p(cGrn, "nothing urgent — keep it up."))
		fmt.Fprintln(w)
		return
	}
	for i, it := range items {
		fmt.Fprintf(w, "    %s %s %s\n", p(cBold+cCyan, itoa(i+1)+"."), p(riskColor(it.risk)+cBold, "["+it.risk.String()+"]"), p(cBold, it.what))
		if it.where != "" {
			fmt.Fprintf(w, "       %s\n", p(cGray, it.where))
		}
		fmt.Fprintf(w, "       %s %s\n", p(cGrn, "→"), it.how)
	}
	fmt.Fprintln(w)
}

func auditFooter(w io.Writer, r auditResult, p paint) {
	rule(w, p, "COVERAGE")
	fmt.Fprintln(w, "    "+p(cDim, "secrets · dependencies · SAST (C#/JS/TS/Py/Go/Ruby/PHP) · IaC · surface · exploit-linking"))
	fmt.Fprintln(w, "    "+p(cGray, "andas — sift real security risk from the noise · read-only"))
	fmt.Fprintln(w)
}

// --- priority synthesis ---------------------------------------------------

type priority struct {
	risk  finding.Severity
	what  string
	where string
	how   string
}

// prioritise ranks the highest-leverage remediation actions across all results:
// exploitable endpoints first, then findings by real risk.
func prioritise(r auditResult) []priority {
	var out []priority
	// Exploitable unauthenticated endpoints reaching a sink are the sharpest edge.
	for _, t := range r.Candidates {
		if t.route.Auth || len(t.sinks) == 0 {
			continue
		}
		s := t.sinks[0]
		out = append(out, priority{
			risk:  finding.SevHigh,
			what:  "Unauthenticated " + s.Title,
			where: t.route.Method + " " + t.route.Path + "  ·  " + s.File + ":" + itoa(s.Line),
			how:   firstNonEmpty(s.Fix, "Add authentication and validate all input on this endpoint."),
		})
	}
	// Then the highest real-risk findings.
	for _, f := range topFindings(r.Findings, 8) {
		rr := f.RealRisk()
		if rr < finding.SevMedium {
			continue
		}
		out = append(out, priority{
			risk:  rr,
			what:  f.Title,
			where: f.File + ":" + itoa(f.Line),
			how:   firstNonEmpty(f.Fix, "Review and remediate."),
		})
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// --- shared helpers -------------------------------------------------------

func topFindings(fs []finding.Finding, n int) []finding.Finding {
	real := make([]finding.Finding, 0, len(fs))
	for _, f := range fs {
		if f.RealRisk() >= finding.SevLow {
			real = append(real, f)
		}
	}
	sort.SliceStable(real, func(i, j int) bool { return real[i].RealRisk() > real[j].RealRisk() })
	if len(real) > n {
		real = real[:n]
	}
	return real
}

func countReal(fs []finding.Finding) int {
	n := 0
	for _, f := range fs {
		if f.RealRisk() >= finding.SevLow {
			n++
		}
	}
	return n
}

func tally(p paint, code, label string, n int) string {
	col := code
	if n == 0 {
		col = cGray
	}
	return p(col, fmt.Sprintf("%s %d", label, n))
}

func gradeColor(g string) string {
	switch g[0] {
	case 'A':
		return cGrn
	case 'B':
		return cCyan
	case 'C':
		return cYel
	case 'D':
		return cOrng
	default:
		return cRed
	}
}

func riskColor(s finding.Severity) string {
	switch s {
	case finding.SevCritical, finding.SevHigh:
		return cRed
	case finding.SevMedium:
		return cYel
	case finding.SevLow:
		return cGray
	default:
		return cGray
	}
}

func authColor(n int) string {
	if n > 0 {
		return cYel
	}
	return cGrn
}

func riskWhen(n int) string {
	if n > 0 {
		return cRed + cBold
	}
	return cGrn
}

func pad(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

func dur(d interface{ Seconds() float64 }) string {
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// --- JSON -----------------------------------------------------------------

func auditJSON(w io.Writer, r auditResult) error {
	type outT struct {
		Target      string            `json:"target"`
		Grade       string            `json:"grade"`
		Score       int               `json:"score"`
		RiskCounts  map[string]int    `json:"risk_counts"`
		Endpoints   int               `json:"endpoints"`
		NoAuth      int               `json:"no_auth_endpoints"`
		Exploitable int               `json:"exploitable_endpoints"`
		Chains      []string          `json:"attack_chains"`
		Findings    []finding.Finding `json:"findings"`
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(outT{
		Target: r.Root, Grade: r.Grade, Score: r.Score, RiskCounts: r.Counts,
		Endpoints: r.Endpoints, NoAuth: r.NoAuth, Exploitable: r.Exploitable,
		Chains: r.Chains, Findings: r.Findings,
	})
}

var _ = surface.Route{} // keep the surface import if renderers are trimmed
