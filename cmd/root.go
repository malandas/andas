// Package cmd wires the andas command-line interface. It uses only the standard
// library so a `go build` produces a single dependency-free binary per OS.
package cmd

import (
	"fmt"
	"os"
)

const version = "0.2.1"

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
  andas scan [path]     scan a directory (default: current)
  andas version         print version
  andas help            show this help

run "andas scan -h" for scan flags`)
}
