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
	Validate bool // perform live validation of secrets
	Offline  bool // make no network calls at all (no validation, no OSV)
	Entropy  bool // flag high-entropy secret-like values beyond the known rules
	TimeoutS int  // per-request network timeout, seconds
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
// the size limit, skipping the directories in skipDirs.
func WalkText(root string) ([]TextFile, error) {
	var out []TextFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort the whole walk
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
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

// isBinary uses the same heuristic as git: a NUL byte in the first 8000 bytes.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}
