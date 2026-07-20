package gitmeta

import (
	"strings"
	"testing"
	"time"
)

func TestDescribe(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	since := time.Date(2025, 12, 4, 0, 0, 0, 0, time.UTC) // 47 days earlier
	got := Describe(since, now)
	if !strings.Contains(got, "47 days") || !strings.Contains(got, "2025-12-04") {
		t.Errorf("Describe = %q, want ~47 days since 2025-12-04", got)
	}
	// A future timestamp must clamp to 0, never go negative.
	if g := Describe(now, since); !strings.Contains(g, "~0 days") {
		t.Errorf("future timestamp not clamped: %q", g)
	}
}
