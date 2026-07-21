// Package githistory scans a repository's entire git history for secrets — not
// just the current working tree. This is andas's sharpest edge: a credential
// deleted from HEAD three months ago still sits in history, and history is
// public the moment the repo is. Paired with live validation, andas can say the
// thing that actually matters: "you removed this, but it still works."
package githistory

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

// blob is one unique object in the repository's history.
type blob struct {
	SHA     string
	Content []byte
}

// isRepo reports whether dir is inside a git working tree.
func isRepo(dir string) bool {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// allBlobShas returns every blob object hash in the repository (all branches,
// all history), skipping objects larger than maxBlobBytes.
func allBlobShas(dir string, maxBlobBytes int) ([]string, error) {
	cmd := exec.Command("git", "-C", dir, "cat-file",
		"--batch-all-objects", "--batch-check=%(objecttype) %(objectname) %(objectsize)")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var shas []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 || fields[0] != "blob" {
			continue
		}
		if size, err := strconv.Atoi(fields[2]); err == nil && size <= maxBlobBytes {
			shas = append(shas, fields[1])
		}
	}
	return shas, sc.Err()
}

// readBlobs streams the contents of the given blobs via a single `git cat-file
// --batch` process — one child process for the whole set, not one per blob.
func readBlobs(dir string, shas []string) ([]blob, error) {
	cmd := exec.Command("git", "-C", dir, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		w := bufio.NewWriter(stdin)
		for _, sha := range shas {
			w.WriteString(sha)
			w.WriteByte('\n')
		}
		w.Flush()
	}()

	var blobs []blob
	r := bufio.NewReader(stdout)
	for {
		header, err := r.ReadString('\n')
		if err != nil {
			break // EOF: all objects consumed
		}
		// header: "<sha> <type> <size>"
		fields := strings.Fields(strings.TrimSpace(header))
		if len(fields) != 3 {
			continue
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		content := make([]byte, size)
		if _, err := readFull(r, content); err != nil {
			break
		}
		r.ReadByte() // trailing newline after content
		if fields[1] == "blob" && !isBinary(content) {
			blobs = append(blobs, blob{SHA: fields[0], Content: content})
		}
	}
	cmd.Wait()
	return blobs, nil
}

// commitInfo locates the first commit that introduced a blob, for attribution.
// Run only for the handful of blobs that actually contain a secret.
func commitInfo(dir, sha string) (commit, author, date string) {
	cmd := exec.Command("git", "-C", dir, "log", "--all", "--find-object="+sha,
		"--format=%h\x1f%an\x1f%ad", "--date=short", "-1")
	out, err := cmd.Output()
	if err != nil {
		return "", "", ""
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "\x1f", 3)
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

// inWorkingTree reports whether the exact secret still appears in a tracked
// file at HEAD — i.e. whether this is a live-in-code leak or a history-only one.
func inWorkingTree(dir, secret string) bool {
	// `-e <pattern>` marks the secret as the pattern, never an option — so a
	// value like "--open-files-in-pager=…" can't turn into git-grep argument
	// injection when scanning a malicious repo's history.
	cmd := exec.Command("git", "-C", dir, "grep", "-lF", "-e", secret)
	out, _ := cmd.Output() // exit code 1 (no match) is expected, ignore err
	return len(strings.TrimSpace(string(out))) > 0
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}
