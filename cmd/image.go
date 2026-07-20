package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/malandas/andas/internal/report"
	"github.com/malandas/andas/internal/scanner/image"
)

// runImage implements `andas image <tarball>`: scan a `docker save`d image for
// vulnerable OS packages.
func runImage(args []string) int {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	var (
		asJSON  = fs.Bool("json", false, "emit JSON instead of the table")
		noColor = fs.Bool("no-color", false, "disable coloured output")
		timeout = fs.Int("timeout", 20, "OSV network timeout, seconds")
		failOn  = fs.String("fail-on", "high", "exit non-zero if real risk reaches this level")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: andas image <image.tar> [flags]")
		fmt.Fprintln(os.Stderr, "\nScan a container image tarball (from `docker save -o image.tar <image>`)")
		fmt.Fprintln(os.Stderr, "for vulnerable OS packages (Debian, Ubuntu, Alpine).\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return 2
	}
	tarball := fs.Arg(0)
	if info, err := os.Stat(tarball); err != nil || info.IsDir() {
		fmt.Fprintf(os.Stderr, "andas: %q is not a readable image tarball\n", tarball)
		return 2
	}

	findings, err := image.ScanTarball(tarball, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}

	if *asJSON {
		if err := report.JSON(os.Stdout, findings); err != nil {
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
	} else {
		report.Text(os.Stdout, findings, !*noColor)
	}
	if report.HighestRisk(findings) >= parseSeverity(*failOn) {
		return 1
	}
	return 0
}
