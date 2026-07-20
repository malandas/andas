// Package gitmeta reads read-only metadata from git — never writes — so andas
// can tell you *how long* a secret has been exposed. A secret that's been in the
// tree for six months is a very different emergency from one added today.
package gitmeta

import (
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Available reports whether dir is inside a git working tree.
func Available(dir string) bool {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// LineIntroduced returns when the given line of a file was last written, via
// git blame. ok is false if blame can't determine it (untracked, not a repo).
func LineIntroduced(dir, file string, line int) (t time.Time, ok bool) {
	if line < 1 {
		return t, false
	}
	spec := strconv.Itoa(line) + "," + strconv.Itoa(line)
	out, err := exec.Command("git", "-C", dir, "blame", "-L", spec, "--porcelain", "--", file).Output()
	if err != nil {
		return t, false
	}
	for _, ln := range strings.Split(string(out), "\n") {
		if rest, found := strings.CutPrefix(ln, "author-time "); found {
			if unix, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return time.Unix(unix, 0), true
			}
		}
	}
	return t, false
}

// Describe renders an exposure phrase relative to now, e.g.
// "exposed ~47 days (since 2025-11-08)". now is passed in so callers control
// the clock (and tests stay deterministic).
func Describe(t, now time.Time) string {
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return "exposed ~" + strconv.Itoa(days) + " days (since " + t.Format("2006-01-02") + ")"
}
