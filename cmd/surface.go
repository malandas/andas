package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/recon"
	"github.com/malandas/andas/internal/scanner/surface"
)

// runSurface implements `andas surface [path]` — map a codebase's HTTP attack
// surface for an authorised security assessment.
func runSurface(args []string) int {
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)
	var (
		asJSON  = fs.Bool("json", false, "emit JSON instead of the table")
		noColor = fs.Bool("no-color", false, "disable coloured output")
		noAuth  = fs.Bool("no-auth-only", false, "show only endpoints with no visible auth check")
		openAPI  = fs.String("openapi", "", "write an OpenAPI 3.0 spec of the surface to this file (import into Burp Suite / OWASP ZAP)")
		requests = fs.String("requests", "", "write one raw HTTP request file per endpoint into this dir (paste into Burp Repeater)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: andas surface [path] [flags]")
		fmt.Fprintln(os.Stderr, "\nMap the HTTP endpoints a codebase exposes (Express, Flask/FastAPI,")
		fmt.Fprintln(os.Stderr, "Django, Rails, Gin, Laravel) for AUTHORISED assessment — flags routes")
		fmt.Fprintln(os.Stderr, "with no visible auth and those taking user input.")
		fmt.Fprintln(os.Stderr, "\nExport for pentest tooling: --openapi (Burp/ZAP import) or --requests")
		fmt.Fprintln(os.Stderr, "(raw HTTP files for Burp Repeater).\n\nFlags:")
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

	routes, err := surface.Map(root, scanner.LoadIgnore(root))
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: %v\n", err)
		return 1
	}
	if *noAuth {
		var f []surface.Route
		for _, r := range routes {
			if !r.Auth {
				f = append(f, r)
			}
		}
		routes = f
	}
	// Unauthenticated + input-taking routes first — the juiciest targets.
	sort.SliceStable(routes, func(i, j int) bool {
		return score(routes[i]) > score(routes[j])
	})

	if *openAPI != "" {
		ignore := scanner.LoadIgnore(root)
		params := recon.Params(root, ignore)
		f, err := os.Create(*openAPI)
		if err != nil {
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
		if err := writeOpenAPI(f, routes, params); err != nil {
			f.Close()
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
		f.Close()
		fmt.Fprintf(os.Stderr, "andas: wrote OpenAPI spec (%d endpoints, %d params) to %s\n", len(routes), len(params), *openAPI)
		fmt.Fprintln(os.Stderr, "       import into Burp (Target → OpenAPI) or ZAP (Import → OpenAPI); set the TARGET server first.")
		return 0
	}

	if *requests != "" {
		params := recon.Params(root, scanner.LoadIgnore(root))
		n, err := writeRequests(*requests, routes, params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "andas: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "andas: wrote %d raw HTTP request(s) to %s/\n", n, *requests)
		fmt.Fprintln(os.Stderr, "       open one, replace Host: TARGET, and paste into Burp Repeater (Ctrl/Cmd-R).")
		return 0
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return boolExit(enc.Encode(routes) == nil)
	}
	printSurface(routes, !*noColor)
	return 0
}

// score ranks a route by how attractive it is to test.
func score(r surface.Route) int {
	s := 0
	if !r.Auth {
		s += 2
	}
	if r.UserInput {
		s++
	}
	return s
}

func printSurface(routes []surface.Route, color bool) {
	const (
		reset = "\033[0m"
		bold  = "\033[1m"
		red   = "\033[31m"
		yel   = "\033[33m"
		gray  = "\033[90m"
		grn   = "\033[32m"
	)
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}
	fmt.Println()
	fmt.Println(c(bold, "  andas — attack surface"))
	fmt.Println(c(gray, "  ─────────────────────────"))
	if len(routes) == 0 {
		fmt.Println(c(gray, "  no HTTP routes detected."))
		fmt.Println()
		return
	}
	var noAuth int
	for _, r := range routes {
		flags := ""
		if !r.Auth {
			flags += c(red, " ⚠ no-auth")
			noAuth++
		} else {
			flags += c(grn, " 🔒 auth")
		}
		if r.UserInput {
			flags += c(yel, " ⌨ input")
		}
		method := fmt.Sprintf("%-6s", r.Method)
		fmt.Printf("  %s %-28s%s\n", c(bold, method), r.Path, flags)
		fmt.Printf("         %s  %s\n", c(gray, r.File+":"+itoa(r.Line)), c(gray, r.Framework))
	}
	fmt.Println()
	fmt.Printf("%s\n", c(bold, fmt.Sprintf("  %d endpoint(s), %d with no visible auth", len(routes), noAuth)))
	fmt.Println(c(gray, "  for authorised testing only."))
	fmt.Println()
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func boolExit(ok bool) int {
	if ok {
		return 0
	}
	return 1
}
