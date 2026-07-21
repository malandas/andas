package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/config"
	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/gitmeta"
	"github.com/malandas/andas/internal/owasp"
	"github.com/malandas/andas/internal/report"
	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/deps"
	"github.com/malandas/andas/internal/scanner/iac"
	"github.com/malandas/andas/internal/scanner/sast"
	"github.com/malandas/andas/internal/scanner/secrets"
	"github.com/malandas/andas/internal/scanner/surface"
)

// runReview implements `andas review [path]` — a security code review. It runs
// every analysis, then presents the results the way a human reviewer would: a
// verdict (request changes / approve), grouped by file, each finding as a
// review comment with the risk, the reason, and a concrete fix. With --since it
// reviews only what changed on the branch — a PR reviewer in one command.
func runReview(args []string) int {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	var (
		since    = fs.String("since", "", "review only files changed since this git ref (e.g. main) — PR mode")
		offline  = fs.Bool("offline", false, "make no network calls at all")
		noColor  = fs.Bool("no-color", false, "disable coloured output")
		mdOut    = fs.String("markdown", "", "write the review as Markdown (postable to a PR) to this path")
		htmlOut  = fs.String("html", "", "write an interactive, shareable HTML review to this path")
		sarifOut = fs.String("sarif", "", "write SARIF for GitHub code scanning (inline PR annotations) to this path")
		failOn   = fs.String("fail-on", "high", "request changes / exit non-zero at this real-risk level (info|low|medium|high|critical)")
		timeout  = fs.Int("timeout", 15, "per-request network timeout, seconds")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: andas review [path] [flags]")
		fmt.Fprintln(os.Stderr, "\nSecurity code review: runs every analysis and reports findings as a")
		fmt.Fprintln(os.Stderr, "reviewer would — a verdict, grouped by file, with reasons and fixes.")
		fmt.Fprintln(os.Stderr, "Use --since main to review just a branch's changes.\n\nFlags:")
		fs.PrintDefaults()
	}
	root, code := auditParse(fs, args) // shares the path-harvesting parser
	if code >= 0 {
		return code
	}

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
	all, err := runScanners([]scanner.Scanner{secrets.New(), deps.New(), sast.New(), iac.New()}, root, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}
	all = filterDisabled(all, cfg)

	scope := "the whole project"
	preexisting := 0
	if *since != "" {
		// Hunk-level: comment only on lines this change actually touched, and
		// separate them from pre-existing issues that merely live in the same file.
		changedLines, err := gitmeta.ChangedLines(root, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "andas: --since %q: %v\n", *since, err)
			return 2
		}
		var introduced []finding.Finding
		for _, f := range all {
			abs := f.File
			if !filepath.IsAbs(abs) {
				abs, _ = filepath.Abs(filepath.Join(root, f.File))
			}
			if _, touched := changedLines[abs]; !touched {
				continue // not in a file this change touched at all
			}
			if gitmeta.Introduced(changedLines, abs, f.Line) {
				introduced = append(introduced, f)
			} else {
				preexisting++ // in a touched file, but not on a changed line
			}
		}
		all = introduced
		scope = fmt.Sprintf("%d changed file(s) vs %s", len(changedLines), *since)
	}

	rev := buildReview(all)
	rev.preexisting = preexisting
	if routes, err := surface.Map(root, opts.IgnorePaths); err == nil {
		rev.conventions = checkConventions(routes)
	}

	// Security delta: how this change moved the whole project's posture vs the
	// base. Best-effort — if the base can't be materialised, skip it.
	var delta *deltaResult
	if *since != "" {
		if d, ok := computeSecurityDelta(root, *since, opts, all); ok {
			delta = &d
		}
	}
	printReview(os.Stdout, rev, delta, root, scope, !*noColor)
	if *mdOut != "" {
		if err := writeFile(*mdOut, func(w io.Writer) error { return reviewMarkdown(w, rev, scope) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing review: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: review written to %s\n", *mdOut)
	}
	if *htmlOut != "" {
		if err := writeFile(*htmlOut, func(w io.Writer) error { return reviewHTML(w, rev, delta, scope) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing HTML review: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: interactive review written to %s\n", *htmlOut)
	}
	if *sarifOut != "" {
		if err := writeFile(*sarifOut, func(w io.Writer) error { return report.SARIF(w, all) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing SARIF: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: SARIF written to %s (upload with github/codeql-action/upload-sarif)\n", *sarifOut)
	}

	// A reviewer that blocks the merge: request changes at/above the threshold —
	// but only on findings it stands behind (tentative ones don't fail CI).
	if rev.blocking >= parseSeverity(*failOn) && rev.blocking > finding.SevInfo {
		return 1
	}
	return 0
}

// reviewData is the review grouped for presentation.
type reviewData struct {
	files       []reviewFile
	counts      map[finding.Severity]int
	total       int
	highest     finding.Severity // highest real risk among all findings
	blocking    finding.Severity // highest among firm/confirmed findings (drives the verdict)
	tentative   int              // findings andas couldn't fully stand behind
	preexisting int              // issues in touched files but not on lines this change introduced
	conventions []conventionDeviation
}

type reviewFile struct {
	path     string
	findings []finding.Finding
}

func buildReview(all []finding.Finding) reviewData {
	byFile := map[string][]finding.Finding{}
	counts := map[finding.Severity]int{}
	highest, blocking := finding.SevInfo, finding.SevInfo
	tentative := 0
	for _, f := range all {
		rr := f.RealRisk()
		byFile[f.File] = append(byFile[f.File], f)
		counts[rr]++
		if rr > highest {
			highest = rr
		}
		// A reviewer only blocks the merge on findings it stands behind; a
		// tentative one (test code, unverified heuristic) is shown but doesn't
		// force "request changes".
		if f.Confidence() >= finding.Firm {
			if rr > blocking {
				blocking = rr
			}
		} else {
			tentative++
		}
	}
	var files []reviewFile
	for p, fs := range byFile {
		sort.SliceStable(fs, func(i, j int) bool {
			if ri, rj := fs[i].RealRisk(), fs[j].RealRisk(); ri != rj {
				return ri > rj
			}
			return fs[i].Line < fs[j].Line
		})
		files = append(files, reviewFile{path: p, findings: fs})
	}
	// Files with the most severe issue first, then by count.
	sort.SliceStable(files, func(i, j int) bool {
		hi, hj := fileHighest(files[i]), fileHighest(files[j])
		if hi != hj {
			return hi > hj
		}
		return len(files[i].findings) > len(files[j].findings)
	})
	return reviewData{files: files, counts: counts, total: len(all), highest: highest, blocking: blocking, tentative: tentative}
}

func fileHighest(rf reviewFile) finding.Severity {
	h := finding.SevInfo
	for _, f := range rf.findings {
		if rr := f.RealRisk(); rr > h {
			h = rr
		}
	}
	return h
}

// reviewTLDR is the reviewer's opening line: what the change introduces and
// where to start looking — the one sentence that orients a busy human.
func reviewTLDR(rev reviewData) string {
	if rev.total == 0 {
		return "This change introduces no new security risk."
	}
	var parts []string
	for _, s := range []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow} {
		if n := rev.counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(s.String())))
		}
	}
	top := rev.files[0].findings[0] // sorted: most severe, in the riskiest file
	s := fmt.Sprintf("This change introduces %s across %d file(s). Start with %s in %s:%d",
		strings.Join(parts, ", "), len(rev.files), top.Title, shortFile(top.File), top.Line)
	if top.Context.UserInput {
		s += " — user input reaches it"
	}
	return s + "."
}

// reviewVerdict maps the worst real risk to a reviewer's decision.
func reviewVerdict(highest finding.Severity, total int) (icon, text string) {
	switch {
	case total == 0:
		return "✅", "APPROVE — no security issues found. LGTM."
	case highest >= finding.SevHigh:
		return "⛔", "REQUEST CHANGES — high-risk issue(s) must be addressed before merge."
	case highest == finding.SevMedium:
		return "💬", "COMMENT — some issues to consider; not blocking."
	default:
		return "✅", "APPROVE — only minor notes."
	}
}

func printReview(w io.Writer, rev reviewData, delta *deltaResult, root, scope string, color bool) {
	p := painter(color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+p(cBold+cCyan, "andas")+p(cDim, " · security code review"))
	fmt.Fprintln(w, "  "+p(cGray, "reviewing "+scope+"   ·   "+root))
	fmt.Fprintln(w)

	icon, text := reviewVerdict(rev.blocking, rev.total)
	vc := cGrn
	if rev.blocking >= finding.SevHigh {
		vc = cRed
	} else if rev.blocking == finding.SevMedium {
		vc = cYel
	}
	rule(w, p, "VERDICT")
	fmt.Fprintf(w, "    %s %s\n", icon, p(vc+cBold, text))
	fmt.Fprintf(w, "    %s\n", p(cDim, reviewTLDR(rev)))
	if rev.tentative > 0 {
		fmt.Fprintf(w, "    %s\n", p(cGray, fmt.Sprintf("%d tentative finding(s) shown for review but not blocking (test code / heuristic)", rev.tentative)))
	}
	if delta != nil && delta.worse() {
		fmt.Fprintf(w, "    %s\n", p(cRed, "⚠ this change increases the project's exposure (see delta below)"))
	}
	fmt.Fprintln(w)

	if delta != nil {
		printDelta(w, *delta, "base", color)
	}
	printConventions(w, rev.conventions, color)

	for _, rf := range rev.files {
		rule(w, p, shortFile(rf.path))
		for _, f := range rf.findings {
			rr := f.RealRisk()
			loc := "line " + itoa(f.Line)
			meta := f.Context.CWE
			if cat := owasp.Category(f.Context.CWE); cat != "" {
				meta += " · " + cat
			}
			conf := ""
			switch f.Confidence() {
			case finding.Confirmed:
				conf = p(cGrn, " ✓confirmed")
			case finding.Tentative:
				conf = p(cGray, " ?tentative")
			}
			fmt.Fprintf(w, "  %s %s  %s%s\n", p(riskColor(rr)+cBold, pad(rr.String(), 8)), p(cGray, loc), p(cBold, f.Title), conf)
			if m := strings.TrimSpace(f.Match); m != "" {
				fmt.Fprintf(w, "           %s\n", p(cGray, m))
			}
			if meta != "" {
				fmt.Fprintf(w, "           %s\n", p(cDim, meta))
			}
			if f.Kind == finding.KindCode {
				if fixed, ok := suggestPatch(f.RuleID, strings.TrimSpace(f.Match)); ok {
					fmt.Fprintf(w, "           %s\n", p(cGrn+cBold, "suggested fix:"))
					fmt.Fprintf(w, "           %s\n", p(cRed, "- "+strings.TrimSpace(f.Match)))
					fmt.Fprintf(w, "           %s\n", p(cGrn, "+ "+strings.TrimSpace(fixed)))
				} else if f.Fix != "" {
					fmt.Fprintf(w, "           %s %s\n", p(cGrn, "→"), f.Fix)
				}
			} else if f.Fix != "" {
				fmt.Fprintf(w, "           %s %s\n", p(cGrn, "→"), f.Fix)
			}
		}
		fmt.Fprintln(w)
	}

	rule(w, p, "SUMMARY")
	fmt.Fprintf(w, "    %s   %s   %s   %s\n",
		p(cRed+cBold, fmt.Sprintf("%d critical", rev.counts[finding.SevCritical])),
		p(cRed, fmt.Sprintf("%d high", rev.counts[finding.SevHigh])),
		p(cYel, fmt.Sprintf("%d medium", rev.counts[finding.SevMedium])),
		p(cGray, fmt.Sprintf("%d low", rev.counts[finding.SevLow])),
	)
	fmt.Fprintf(w, "    %s\n", p(cDim, fmt.Sprintf("%d finding(s) across %d file(s)", rev.total, len(rev.files))))
	if rev.preexisting > 0 {
		fmt.Fprintf(w, "    %s\n", p(cGray, fmt.Sprintf("+ %d pre-existing issue(s) in touched files (not introduced by this change)", rev.preexisting)))
	}
	fmt.Fprintln(w)
}

// reviewMarkdown renders the review as Markdown a bot could post on a PR.
func reviewMarkdown(w io.Writer, rev reviewData, scope string) error {
	icon, text := reviewVerdict(rev.highest, rev.total)
	var b strings.Builder
	b.WriteString("## andas — security code review\n\n")
	b.WriteString("_Reviewing " + scope + "._\n\n")
	b.WriteString("### " + icon + " " + text + "\n\n")
	b.WriteString("_" + reviewTLDR(rev) + "_\n\n")
	b.WriteString(fmt.Sprintf("**%d critical · %d high · %d medium · %d low** across %d file(s).\n\n",
		rev.counts[finding.SevCritical], rev.counts[finding.SevHigh],
		rev.counts[finding.SevMedium], rev.counts[finding.SevLow], len(rev.files)))
	if rev.preexisting > 0 {
		b.WriteString(fmt.Sprintf("_%d pre-existing issue(s) in touched files are not counted above (not introduced by this change)._\n\n", rev.preexisting))
	}

	for _, rf := range rev.files {
		b.WriteString("### `" + rf.path + "`\n\n")
		for _, f := range rf.findings {
			rr := f.RealRisk()
			b.WriteString(fmt.Sprintf("- **%s** (line %d) — %s", rr.String(), f.Line, f.Title))
			if f.Context.CWE != "" {
				b.WriteString(" _(" + f.Context.CWE + ")_")
			}
			b.WriteString("\n")
			if m := strings.TrimSpace(f.Match); m != "" {
				b.WriteString("  ```\n  " + m + "\n  ```\n")
			}
			if fixed, ok := suggestPatch(f.RuleID, strings.TrimSpace(f.Match)); ok && f.Kind == finding.KindCode {
				// GitHub renders ```suggestion blocks as a one-click "apply" on the PR.
				b.WriteString("  ```suggestion\n  " + strings.TrimSpace(fixed) + "\n  ```\n")
			} else if f.Fix != "" {
				b.WriteString("  → " + f.Fix + "\n")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\n_Generated by andas — real security risk, not noise._\n")
	_, err := io.WriteString(w, b.String())
	return err
}
