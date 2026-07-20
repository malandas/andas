// Package scanner defines the contract every detector implements, plus the
// shared file-walking machinery so each scanner doesn't reinvent it.
package scanner

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// Scanner is one detection module (secrets, vulnerabilities, ...).
type Scanner interface {
	// Name is a short identifier shown in output.
	Name() string
	// Scan inspects root and returns any findings.
	Scan(root string, opts Options) ([]finding.Finding, error)
}

// Options carries run-wide settings down to individual scanners.
type Options struct {
	Validate    bool     // perform live validation of secrets
	Offline     bool     // make no network calls at all (no validation, no OSV)
	Entropy     bool     // flag high-entropy secret-like values beyond the known rules
	TimeoutS    int      // per-request network timeout, seconds
	IgnorePaths []string // .andasignore patterns for file-based scanners
}

// Directories we never descend into: noise, vendored code, and VCS internals.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true,
	"dist": true, "build": true, ".next": true, "target": true,
}

const maxFileBytes = 2 << 20 // 2 MiB: skip anything larger, it's rarely source

// TextFile is a source file read into memory, ready for line-based scanning.
type TextFile struct {
	Path  string
	Lines []string
}

// WalkText walks root and yields every readable, non-binary text file under
// the size limit, skipping the directories in skipDirs and anything matching a
// user-supplied ignore pattern (from .andasignore).
func WalkText(root string, ignore []string) ([]TextFile, error) {
	var out []TextFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort the whole walk
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if skipDirs[d.Name()] || matchesIgnore(rel, d.Name(), ignore) {
				return filepath.SkipDir
			}
			return nil
		}
		if matchesIgnore(rel, d.Name(), ignore) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > maxFileBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || isBinary(data) {
			return nil
		}
		out = append(out, TextFile{
			Path:  path,
			Lines: strings.Split(string(data), "\n"),
		})
		return nil
	})
	return out, err
}

// LoadIgnore reads .andasignore from root, returning its patterns. A missing
// file yields no patterns. Blank lines and lines starting with '#' are skipped.
func LoadIgnore(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, ".andasignore"))
	if err != nil {
		return nil
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, strings.TrimSuffix(line, "/"))
	}
	return patterns
}

// matchesIgnore reports whether a path should be skipped. A pattern matches when
// it globs the relative path or the base name, or appears as a literal path
// segment (so `build` or `src/generated` both work like a .gitignore entry).
func matchesIgnore(rel, base string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range patterns {
		p = filepath.ToSlash(p)
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if rel == p || strings.HasPrefix(rel, p+"/") || strings.Contains(rel, "/"+p+"/") {
			return true
		}
	}
	return false
}

// isBinary uses the same heuristic as git: a NUL byte in the first 8000 bytes.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}
