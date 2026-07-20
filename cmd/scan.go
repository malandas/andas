package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/report"
	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/deps"
	"github.com/malandas/andas/internal/scanner/githistory"
	"github.com/malandas/andas/internal/scanner/iac"
	"github.com/malandas/andas/internal/scanner/sast"
	"github.com/malandas/andas/internal/scanner/secrets"
)

// runScan implements `andas scan [path]`.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		noValidate = fs.Bool("no-validate", false, "skip live validation of secrets")
		offline    = fs.Bool("offline", false, "make no network calls at all (no secret validation, no OSV vuln lookup)")
		history    = fs.Bool("history", false, "also scan the full git history for secrets removed from HEAD")
		noEntropy  = fs.Bool("no-entropy", false, "disable entropy-based detection of unknown/custom secrets")
		baseline   = fs.String("baseline", "", "suppress findings listed in this baseline file")
		updateBase = fs.Bool("update-baseline", false, "write all current findings to --baseline as accepted, then exit")
		asJSON     = fs.Bool("json", false, "emit JSON instead of the table")
		htmlOut    = fs.String("html", "", "write a self-contained HTML report to this path")
		sarifOut   = fs.String("sarif", "", "write a SARIF 2.1.0 report to this path (for CI/code scanning)")
		mdOut      = fs.String("markdown", "", "write a PR-comment-style Markdown report to this path")
		noColor    = fs.Bool("no-color", false, "disable coloured output")
		timeout    = fs.Int("timeout", 15, "per-request network timeout, seconds")
		failOn     = fs.String("fail-on", "high", "exit non-zero if real risk reaches this level (info|low|medium|high|critical)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: andas scan [path] [flags]")
		fmt.Fprintln(os.Stderr, "\nScans a directory for secrets and reports them by REAL risk")
		fmt.Fprintln(os.Stderr, "(live secrets promoted, dead ones demoted). Defaults to the")
		fmt.Fprintln(os.Stderr, "current directory.\n\nFlags:")
		fs.PrintDefaults()
	}
	// The stdlib flag package stops at the first non-flag argument, so a
	// natural invocation like `andas scan ./path --json` would silently ignore
	// --json. Loop the parse, harvesting positional args, so flags and the
	// path may appear in any order.
	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return 2
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
		return 2
	}

	opts := scanner.Options{
		Validate:    !*noValidate && !*offline,
		Offline:     *offline,
		Entropy:     !*noEntropy,
		TimeoutS:    *timeout,
		IgnorePaths: scanner.LoadIgnore(root),
	}

	scanners := []scanner.Scanner{
		secrets.New(),
		deps.New(),
		sast.New(),
		iac.New(),
	}
	if *history {
		scanners = append(scanners, githistory.New())
	}

	var all []finding.Finding
	for _, s := range scanners {
		found, err := s.Scan(root, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "andas: scanner %q failed: %v\n", s.Name(), err)
			return 1
		}
		all = append(all, found...)
	}

	// --update-baseline: accept the current state and stop, so future scans
	// report only what appears afterwards.
	if *updateBase {
		if *baseline == "" {
			fmt.Fprintln(os.Stderr, "andas: --update-baseline requires --baseline <file>")
			return 2
		}
		if err := report.WriteBaseline(*baseline, all, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing baseline: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: baseline written to %s (%d findings accepted)\n", *baseline, len(all))
		return 0
	}

	// --baseline: drop previously-accepted findings before reporting or gating.
	if *baseline != "" {
		b, err := report.LoadBaseline(*baseline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "andas: reading baseline: %v\n", err)
			return 1
		}
		var suppressed int
		all, suppressed = b.Filter(all)
		if suppressed > 0 {
			fmt.Fprintf(os.Stderr, "andas: %d finding(s) suppressed by baseline\n", suppressed)
		}
	}

	if *asJSON {
		if err := report.JSON(os.Stdout, all); err != nil {
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
	} else {
		report.Text(os.Stdout, all, !*noColor)
	}

	if *htmlOut != "" {
		if err := writeFile(*htmlOut, func(w io.Writer) error { return report.HTML(w, all, root) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing HTML: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: HTML report written to %s\n", *htmlOut)
	}
	if *sarifOut != "" {
		if err := writeFile(*sarifOut, func(w io.Writer) error { return report.SARIF(w, all) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing SARIF: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: SARIF report written to %s\n", *sarifOut)
	}
	if *mdOut != "" {
		if err := writeFile(*mdOut, func(w io.Writer) error { return report.Markdown(w, all) }); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing Markdown: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: Markdown report written to %s\n", *mdOut)
	}

	if report.HighestRisk(all) >= parseSeverity(*failOn) {
		return 1
	}
	return 0
}

// writeFile creates path and hands the writer to render.
func writeFile(path string, render func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return render(f)
}

func parseSeverity(s string) finding.Severity {
	switch s {
	case "critical":
		return finding.SevCritical
	case "high":
		return finding.SevHigh
	case "medium":
		return finding.SevMedium
	case "low":
		return finding.SevLow
	default:
		return finding.SevInfo
	}
}
