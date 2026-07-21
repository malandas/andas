package cmd

import (
	"testing"

	"github.com/malandas/andas/internal/scanner/surface"
)

func sr(method, path string, limited bool) surface.Route {
	return surface.Route{Method: method, Path: path, RateLimited: limited}
}

func TestRateLimitConvention_FlagsOutlier(t *testing.T) {
	routes := []surface.Route{
		sr("POST", "/api/login", true),
		sr("POST", "/api/token/refresh", true),
		sr("POST", "/api/password/reset", false), // deviation
		sr("POST", "/api/verify-otp", false),      // deviation
	}
	devs := checkConventions(routes)
	if len(devs) != 2 {
		t.Fatalf("expected 2 deviations, got %d", len(devs))
	}
	got := map[string]bool{}
	for _, d := range devs {
		got[d.route.Path] = true
	}
	if !got["/api/password/reset"] || !got["/api/verify-otp"] {
		t.Errorf("wrong deviations: %+v", devs)
	}
}

func TestRateLimitConvention_NoConventionNoFlag(t *testing.T) {
	// Nobody rate-limits → no convention exists → nothing flagged.
	routes := []surface.Route{
		sr("POST", "/api/login", false),
		sr("POST", "/api/token/refresh", false),
		sr("POST", "/api/password/reset", false),
	}
	if devs := checkConventions(routes); len(devs) != 0 {
		t.Errorf("no rate-limit convention should mean no deviations, got %+v", devs)
	}
	// Everyone rate-limits → consistent → nothing flagged.
	for i := range routes {
		routes[i].RateLimited = true
	}
	if devs := checkConventions(routes); len(devs) != 0 {
		t.Errorf("fully consistent project should have no deviations, got %+v", devs)
	}
}
