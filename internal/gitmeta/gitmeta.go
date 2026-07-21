// Package gitmeta reads read-only metadata from git — never writes — so andas
// can tell you *how long* a secret has been exposed. A secret that's been in the
// tree for six months is a very different emergency from one added today.
package gitmeta

import (
	"os/exec"
	"path/filepath"
	"regexp"
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

// ChangedFiles returns the set of files that differ between ref and the working
// tree (tracked changes + untracked files), as absolute paths under root. It
// powers `--since`, so a scan can look only at what a branch or PR touched.
func ChangedFiles(root, ref string) (map[string]bool, error) {
	out := map[string]bool{}
	// Committed/staged/unstaged changes vs the ref.
	diff, err := exec.Command("git", "-C", root, "diff", "--name-only", ref).Output()
	if err != nil {
		return nil, err
	}
	// Plus files not yet tracked at all (a brand-new secret in a new file).
	untracked, _ := exec.Command("git", "-C", root, "ls-files", "--others", "--exclude-standard").Output()

	for _, block := range [][]byte{diff, untracked} {
		for _, rel := range strings.Split(string(block), "\n") {
			rel = strings.TrimSpace(rel)
			if rel == "" {
				continue
			}
			if abs, err := filepath.Abs(filepath.Join(root, rel)); err == nil {
				out[abs] = true
			}
		}
	}
	return out, nil
}

var (
	reDiffFile = regexp.MustCompile(`^\+\+\+ b/(.*)$`)
	reDiffHunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
)

// ChangedLines returns, per file (absolute path), the set of NEW-side line
// numbers the working tree adds or modifies versus ref — the exact lines a PR
// touches. A wholly new (untracked) file maps to {0: true}, meaning "every line
// is new". This lets a review comment only on what the change introduced.
func ChangedLines(root, ref string) (map[string]map[int]bool, error) {
	diff, err := exec.Command("git", "-C", root, "diff", "--unified=0", "--no-color", ref).Output()
	if err != nil {
		return nil, err
	}
	out := map[string]map[int]bool{}
	cur := ""
	newLine := 0
	for _, line := range strings.Split(string(diff), "\n") {
		switch {
		case reDiffFile.MatchString(line):
			m := reDiffFile.FindStringSubmatch(line)
			if abs, err := filepath.Abs(filepath.Join(root, m[1])); err == nil {
				cur = abs
				if out[cur] == nil {
					out[cur] = map[int]bool{}
				}
			}
		case reDiffHunk.MatchString(line):
			newLine, _ = strconv.Atoi(reDiffHunk.FindStringSubmatch(line)[1])
		case cur != "" && strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			out[cur][newLine] = true
			newLine++
		}
	}
	if untracked, err := exec.Command("git", "-C", root, "ls-files", "--others", "--exclude-standard").Output(); err == nil {
		for _, rel := range strings.Split(string(untracked), "\n") {
			if rel = strings.TrimSpace(rel); rel == "" {
				continue
			}
			if abs, err := filepath.Abs(filepath.Join(root, rel)); err == nil {
				out[abs] = map[int]bool{0: true}
			}
		}
	}
	return out, nil
}

// Introduced reports whether (file, line) is part of what the change added —
// either the file is wholly new, or that specific line was touched.
func Introduced(changed map[string]map[int]bool, file string, line int) bool {
	lines, ok := changed[file]
	if !ok {
		return false
	}
	return lines[0] || lines[line]
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
