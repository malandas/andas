package cmd

import (
	"fmt"
	"io"

	"github.com/malandas/andas/internal/scanner/surface"
)

// A conventionDeviation is an endpoint that breaks a pattern the rest of the
// project follows — the subtle bug static rules miss. andas infers the norm
// from the majority, then flags the odd one out.
type conventionDeviation struct {
	route      surface.Route
	convention string // what the peers do that this endpoint doesn't
}

// checkConventions infers project conventions from the discovered routes and
// returns the endpoints that deviate. Deterministic: the norm comes from the
// code itself, not a hard-coded list.
func checkConventions(routes []surface.Route) []conventionDeviation {
	var out []conventionDeviation
	out = append(out, rateLimitConvention(routes)...)
	return out
}

// rateLimitConvention: if the project rate-limits SOME of its sensitive
// endpoints (login/token/reset/OTP…), it clearly intends to — so a sensitive
// endpoint left without a limit is very likely an oversight (brute-force /
// enumeration gap), not a deliberate choice.
func rateLimitConvention(routes []surface.Route) []conventionDeviation {
	var sensitive []surface.Route
	limited := 0
	for _, r := range routes {
		if reSensitive.MatchString(r.Path) {
			sensitive = append(sensitive, r)
			if r.RateLimited {
				limited++
			}
		}
	}
	// The convention only exists if the team uses rate limiting on these AND
	// isn't already applying it everywhere.
	if limited == 0 || len(sensitive) < 3 || limited == len(sensitive) {
		return nil
	}
	var out []conventionDeviation
	for _, r := range sensitive {
		if !r.RateLimited {
			out = append(out, conventionDeviation{
				route:      r,
				convention: fmt.Sprintf("%d of the project's sensitive endpoints are rate-limited; this one isn't", limited),
			})
		}
	}
	return out
}

// printConventions renders the convention-deviation section of a report.
func printConventions(w io.Writer, devs []conventionDeviation, color bool) {
	if len(devs) == 0 {
		return
	}
	p := painter(color)
	rule(w, p, "CONVENTION DEVIATIONS")
	fmt.Fprintf(w, "    %s\n", p(cDim, "endpoints that break a pattern the rest of the project follows"))
	for i, d := range devs {
		if i == 8 {
			fmt.Fprintf(w, "     %s\n", p(cGray, fmt.Sprintf("… and %d more", len(devs)-8)))
			break
		}
		fmt.Fprintf(w, "  %s %-26s %s\n", p(cBold, pad(d.route.Method, 6)), d.route.Path, p(cYel, "⚖ deviation"))
		fmt.Fprintf(w, "         %s\n", p(cGray, d.convention))
	}
	fmt.Fprintln(w)
}
