package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/report"
	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/secrets"
)

// runScan implements `andas scan [path]`.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		noValidate = fs.Bool("no-validate", false, "skip live validation of secrets (offline mode)")
		asJSON     = fs.Bool("json", false, "emit JSON instead of the table")
		noColor    = fs.Bool("no-color", false, "disable coloured output")
		timeout    = fs.Int("timeout", 8, "per-validation network timeout, seconds")
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

	opts := scanner.Options{Validate: !*noValidate, TimeoutS: *timeout}

	scanners := []scanner.Scanner{
		secrets.New(),
		// future: reachability.New() for vulnerability findings
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

	if *asJSON {
		if err := report.JSON(os.Stdout, all); err != nil {
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
	} else {
		report.Text(os.Stdout, all, !*noColor)
	}

	if report.HighestRisk(all) >= parseSeverity(*failOn) {
		return 1
	}
	return 0
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
