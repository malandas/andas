// Package cmd wires the naqi command-line interface. It uses only the standard
// library so a `go build` produces a single dependency-free binary per OS.
package cmd

import (
	"fmt"
	"os"
)

const version = "0.1.0"

// Execute is the entry point called by main.
func Execute() int {
	if len(os.Args) < 2 {
		usage()
		return 2
	}
	switch os.Args[1] {
	case "scan":
		return runScan(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("naqi %s\n", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "naqi: unknown command %q\n\n", os.Args[1])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `naqi — sift real security risk from the noise

usage:
  naqi scan [path]     scan a directory (default: current)
  naqi version         print version
  naqi help            show this help

run "naqi scan -h" for scan flags`)
}
