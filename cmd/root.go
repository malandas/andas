// Package cmd wires the andas command-line interface. It uses only the standard
// library so a `go build` produces a single dependency-free binary per OS.
package cmd

import (
	"fmt"
	"os"
)

const version = "1.18.0"

// Execute is the entry point called by main.
func Execute() int {
	if len(os.Args) < 2 {
		welcome()
		return 2
	}
	switch os.Args[1] {
	case "scan":
		return runScan(os.Args[2:])
	case "hook":
		return runHook(os.Args[2:])
	case "image":
		return runImage(os.Args[2:])
	case "surface":
		return runSurface(os.Args[2:])
	case "pentest":
		return runPentest(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("andas %s\n", version)
		return 0
	case "help", "-h", "--help":
		welcome()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "andas: unknown command %q\n\n", os.Args[1])
		usage()
		return 2
	}
}

// welcome prints the banner then the usage text — the friendly no-args screen.
func welcome() {
	fmt.Fprintln(os.Stderr, banner())
	usage()
}

func usage() {
	fmt.Fprintln(os.Stderr, `andas — sift real security risk from the noise

usage:
  andas scan [path]           scan a directory (default: current)
  andas scan . --history      also scan git history for removed secrets
  andas scan . --html r.html  write a shareable HTML report
  andas scan . --sarif r.sarif write SARIF for CI / code scanning
  andas scan . --markdown r.md write a PR-comment-style Markdown report
  andas image <image.tar>     scan a docker-saved image for vulnerable OS packages
  andas surface [path]        map HTTP endpoints & auth gaps (authorised assessment)
  andas pentest [path]        recon report: endpoints → vulns + live creds (authorised)
  andas hook install          install a git pre-commit secret guard
  andas hook uninstall        remove the pre-commit guard
  andas version               print version
  andas help                  show this help

run "andas scan -h" for all scan flags`)
}
