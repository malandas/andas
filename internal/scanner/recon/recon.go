// Package recon extracts offensive-recon intel from source for an AUTHORISED
// assessment: internal hosts/IPs an engagement should note, and the request
// parameters an endpoint reads — a ready fuzzing wordlist. Source-only; it never
// probes a network.
package recon

import (
	"regexp"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/scanner"
)

var (
	// Private / link-local / loopback IPv4.
	rePrivateIP = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|169\.254\.\d{1,3}\.\d{1,3})\b`)
	// Internal-looking hostnames and localhost:port.
	reInternalHost = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:internal|local|svc|corp|intranet|lan|home|test)\b|localhost:\d+`)
	// Request parameter names read from user input.
	reParam = regexp.MustCompile(`req\.(?:query|body|params)\.(\w+)` +
		`|request\.args\.get\(\s*['"](\w+)` +
		`|request\.(?:form|values|POST|GET)\[\s*['"](\w+)` +
		`|\$_(?:GET|POST|REQUEST|COOKIE)\[\s*['"](\w+)` +
		`|params\[:?(\w+)\]` +
		`|c\.(?:Query|Param|PostForm)\(\s*"(\w+)"`)
)

// Hosts returns the unique internal hosts/IPs referenced in the source.
func Hosts(root string, ignore []string) []string {
	set := map[string]bool{}
	forEachLine(root, ignore, func(line string) {
		for _, m := range rePrivateIP.FindAllString(line, -1) {
			set[m] = true
		}
		for _, m := range reInternalHost.FindAllString(line, -1) {
			set[strings.ToLower(m)] = true
		}
	})
	return sorted(set)
}

// Params returns the unique request-parameter names the code reads — a fuzzing
// wordlist scoped to what the app actually consumes.
func Params(root string, ignore []string) []string {
	set := map[string]bool{}
	forEachLine(root, ignore, func(line string) {
		for _, m := range reParam.FindAllStringSubmatch(line, -1) {
			for _, g := range m[1:] {
				if g != "" {
					set[g] = true
				}
			}
		}
	})
	return sorted(set)
}

func forEachLine(root string, ignore []string, fn func(string)) {
	files, _ := scanner.WalkText(root, ignore)
	for _, f := range files {
		for _, line := range f.Lines {
			fn(line)
		}
	}
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
