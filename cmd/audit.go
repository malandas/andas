package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/malandas/andas/internal/config"
	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/deps"
	"github.com/malandas/andas/internal/scanner/iac"
	"github.com/malandas/andas/internal/scanner/sast"
	"github.com/malandas/andas/internal/scanner/secrets"
	"github.com/malandas/andas/internal/scanner/surface"
)

// auditResult is everything one `andas audit` run learns about a codebase,
// fused from every analysis into a single verdict.
type auditResult struct {
	Root       string          `json:"target"`
	Findings   []finding.Finding `json:"findings"`
	Routes     []surface.Route `json:"-"`
	Candidates []target        `json:"-"`
	Chains     []string        `json:"attack_chains"`
	Counts     map[string]int  `json:"risk_counts"` // by real-risk level
	Endpoints  int             `json:"endpoints"`
	NoAuth     int             `json:"no_auth_endpoints"`
	Exploitable int            `json:"exploitable_endpoints"` // no-auth AND reaches a sink
	Score      int             `json:"score"`
	Grade      string          `json:"grade"`
	Elapsed    time.Duration   `json:"-"`
}

// runAudit implements `andas audit [path]` — the single command that runs every
// analysis (secrets, dependencies, SAST, IaC, attack surface, exploit linking)
// and distils them into one graded, prioritised executive report. Read-only.
func runAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	var (
		offline = fs.Bool("offline", false, "make no network calls at all")
		noColor = fs.Bool("no-color", false, "disable coloured output")
		asJSON  = fs.Bool("json", false, "emit the full audit as JSON")
		htmlOut = fs.String("html", "", "write a self-contained executive HTML report to this path")
		failOn  = fs.String("fail-on", "", "exit non-zero if real risk reaches this level (info|low|medium|high|critical)")
		timeout = fs.Int("timeout", 15, "per-request network timeout, seconds")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: andas audit [path] [flags]")
		fmt.Fprintln(os.Stderr, "\nRun every andas analysis at once and print one graded, prioritised")
		fmt.Fprintln(os.Stderr, "security report: secrets, dependencies, SAST, IaC, attack surface, and")
		fmt.Fprintln(os.Stderr, "exploit linking. Read-only.\n\nFlags:")
		fs.PrintDefaults()
	}
	root, code := auditParse(fs, args)
	if code >= 0 {
		return code
	}

	color := !*noColor && colorMode(os.Stdout) != colorNone
	progress := !*asJSON
	cfg, err := config.Load(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: reading .andas.yml: %v\n", err)
		return 1
	}
	opts := scanner.Options{
		Validate:    !*offline,
		Offline:     *offline,
		Entropy:     true,
		TimeoutS:    *timeout,
		IgnorePaths: append(scanner.LoadIgnore(root), cfg.Ignore...),
	}

	start := time.Now()
	step := func(s string) {
		if progress {
			fmt.Fprintf(os.Stderr, "  \033[2m▸ %s\033[0m\n", s)
		}
	}

	// Phase 1 — findings from every scanner.
	step("analysing secrets, dependencies, code & infrastructure")
	all, err := runScanners([]scanner.Scanner{secrets.New(), deps.New(), sast.New(), iac.New()}, root, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}
	all = filterDisabled(all, cfg)

	// Phase 2 — attack surface.
	step("mapping the HTTP attack surface")
	routes, err := surface.Map(root, opts.IgnorePaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}

	// Phase 3 — link endpoints to the sinks they reach; synthesise chains.
	step("linking endpoints to reachable vulnerabilities")
	code2, secretsF := splitFindings(all)
	targets := link(routes, code2)
	res := buildAudit(root, all, routes, targets, secretsF, time.Since(start))

	// Output.
	switch {
	case *asJSON:
		if err := auditJSON(os.Stdout, res); err != nil {
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
	default:
		auditText(os.Stdout, res, color)
	}
	if *htmlOut != "" {
		if err := writeFile(*htmlOut, func(w io.Writer) error { return auditHTML(w, res) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing HTML: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: executive report written to %s\n", *htmlOut)
	}

	// CI gate.
	if *failOn != "" {
		threshold := parseSeverity(*failOn)
		for _, f := range all {
			if f.RealRisk() >= threshold {
				return 1
			}
		}
	}
	return 0
}

// auditParse harvests the optional path positional wherever it appears among flags.
func auditParse(fs *flag.FlagSet, args []string) (string, int) {
	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return "", 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			positional = append(positional, rest[0])
			rest = rest[1:]
		}
	}
	root := "."
	if len(positional) > 0 {
		root = positional[0]
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "andas: %q is not a readable directory\n", root)
		return "", 2
	}
	return root, -1
}

// splitFindings separates code/vuln sinks (for endpoint linking) from secrets.
func splitFindings(all []finding.Finding) (code, secretsF []finding.Finding) {
	for _, f := range all {
		if f.Kind == finding.KindSecret {
			secretsF = append(secretsF, f)
		} else {
			code = append(code, f)
		}
	}
	return
}

// buildAudit computes the counts, exposure, and grade from the raw results.
func buildAudit(root string, all []finding.Finding, routes []surface.Route, targets []target, secretsF []finding.Finding, elapsed time.Duration) auditResult {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	// scoreCounts drives the grade from findings andas stands behind — tentative
	// ones (test-fixture entropy, unverified heuristics) are shown but must not
	// tank the score, or a repo full of test data always reads as "F".
	scoreCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range all {
		counts[f.RealRisk().String()]++
		if f.Confidence() >= finding.Firm {
			scoreCounts[f.RealRisk().String()]++
		}
	}
	var candidates []target
	noAuth, exploitable := 0, 0
	for _, r := range routes {
		if !r.Auth {
			noAuth++
		}
	}
	for _, t := range targets {
		if len(t.sinks) > 0 {
			candidates = append(candidates, t)
			if !t.route.Auth {
				exploitable++
			}
		}
	}
	score := auditScore(scoreCounts, exploitable)
	return auditResult{
		Root: root, Findings: all, Routes: routes, Candidates: candidates,
		Chains: chains(targets, secretsF), Counts: counts,
		Endpoints: len(routes), NoAuth: noAuth, Exploitable: exploitable,
		Score: score, Grade: gradeFor(score), Elapsed: elapsed,
	}
}

// auditScore turns the real-risk tally and exposed surface into a 0–100 posture
// score. Weights are steep for the risks that actually get people breached.
func auditScore(counts map[string]int, exploitable int) int {
	score := 100
	score -= counts["CRITICAL"] * 25
	score -= counts["HIGH"] * 12
	score -= counts["MEDIUM"] * 5
	score -= counts["LOW"] * 1
	score -= exploitable * 8 // an unauthenticated endpoint that reaches a sink
	if score < 0 {
		score = 0
	}
	return score
}

func gradeFor(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func gradeVerdict(grade string) string {
	switch grade[0] {
	case 'A':
		return "Strong posture — no real risk surfaced."
	case 'B':
		return "Good — a few items to tighten."
	case 'C':
		return "Moderate — real risks need attention."
	case 'D':
		return "Weak — address the high-risk findings."
	default:
		return "At risk — fix the critical findings now."
	}
}
