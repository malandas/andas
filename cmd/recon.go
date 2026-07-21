package cmd

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/recon"
	"github.com/malandas/andas/internal/scanner/surface"
)

// runRecon implements `andas recon [path]` — offensive intel from source for an
// authorised engagement: internal hosts, request parameters, and a path/param
// wordlist to feed a fuzzer.
func runRecon(args []string) int {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	var (
		noColor  = fs.Bool("no-color", false, "disable coloured output")
		wordlist = fs.String("wordlist", "", "write a paths+params wordlist to this file (for ffuf/Burp)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: andas recon [path] [flags]")
		fmt.Fprintln(os.Stderr, "\nExtract offensive recon from source for AUTHORISED assessment:")
		fmt.Fprintln(os.Stderr, "internal hosts/IPs, request parameters, and a fuzzing wordlist.\n\nFlags:")
		fs.PrintDefaults()
	}
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
	ignore := scanner.LoadIgnore(root)

	hosts := recon.Hosts(root, ignore)
	params := recon.Params(root, ignore)
	routes, _ := surface.Map(root, ignore)
	paths := uniquePaths(routes)

	const (
		reset, bold, red, yel, gray = "\033[0m", "\033[1m", "\033[31m", "\033[33m", "\033[90m"
	)
	c := func(code, s string) string {
		if *noColor {
			return s
		}
		return code + s + reset
	}
	fmt.Println()
	fmt.Println(c(bold, "  andas — recon (authorised assessment only)"))
	fmt.Println(c(gray, "  ──────────────────────────────────────────"))

	fmt.Printf("\n  %s\n", c(bold, fmt.Sprintf("🌐 internal hosts / IPs (%d)", len(hosts))))
	for _, h := range hosts {
		fmt.Printf("     %s\n", c(red, h))
	}
	if len(hosts) == 0 {
		fmt.Println(c(gray, "     none referenced in source."))
	}

	fmt.Printf("\n  %s\n", c(bold, fmt.Sprintf("🧭 endpoint paths (%d)", len(paths))))
	for _, p := range paths {
		fmt.Printf("     %s\n", p)
	}

	fmt.Printf("\n  %s\n", c(bold, fmt.Sprintf("⌨ request parameters (%d)", len(params))))
	fmt.Printf("     %s\n", c(yel, wrapJoin(params, 68)))
	fmt.Println()

	if *wordlist != "" {
		if err := writeWordlist(*wordlist, paths, params); err != nil {
			fmt.Fprintf(os.Stderr, "andas: writing wordlist: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: wordlist (%d entries) written to %s\n", len(paths)+len(params), *wordlist)
	}
	return 0
}

func uniquePaths(routes []surface.Route) []string {
	set := map[string]bool{}
	for _, r := range routes {
		set[r.Path] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func writeWordlist(path string, paths, params []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	seen := map[string]bool{}
	for _, list := range [][]string{paths, params} {
		for _, e := range list {
			e = trimLeadingSlash(e)
			if e != "" && !seen[e] {
				seen[e] = true
				fmt.Fprintln(f, e)
			}
		}
	}
	return nil
}

func trimLeadingSlash(s string) string {
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}

func wrapJoin(items []string, width int) string {
	out, line := "", ""
	for _, it := range items {
		if len(line)+len(it)+2 > width {
			out += line + "\n     "
			line = ""
		}
		if line != "" {
			line += ", "
		}
		line += it
	}
	return out + line
}
