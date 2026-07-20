// Package cmd wires the andas command-line interface. It uses only the standard
// library so a `go build` produces a single dependency-free binary per OS.
package cmd

import (
	"fmt"
	"os"
)

const version = "0.8.0"

// Execute is the entry point called by main.
func Execute() int {
	if len(os.Args) < 2 {
		usage()
		return 2
	}
	switch os.Args[1] {
	case "scan":
		return runScan(os.Args[2:])
	case "hook":
		return runHook(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("andas %s\n", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "andas: unknown command %q\n\n", os.Args[1])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `andas — sift real security risk from the noise

usage:
  andas scan [path]           scan a directory (default: current)
  andas scan . --history      also scan git history for removed secrets
  andas scan . --html r.html  write a shareable HTML report
  andas scan . --sarif r.sarif write SARIF for CI / code scanning
  andas hook install          install a git pre-commit secret guard
  andas hook uninstall        remove the pre-commit guard
  andas version               print version
  andas help                  show this help

run "andas scan -h" for all scan flags`)
}
