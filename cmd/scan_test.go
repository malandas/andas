package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// silence runs f with stdout/stderr redirected to /dev/null and returns the
// exit code, so scan wiring can be tested without noise.
func silence(f func() int) int {
	old, oldErr := os.Stdout, os.Stderr
	devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout, os.Stderr = devnull, devnull
	defer func() {
		os.Stdout, os.Stderr = old, oldErr
		devnull.Close()
	}()
	return f()
}

func TestRunScan_CleanDirExitsZero(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.js"), []byte("export const ok = true;\n"), 0o644)
	if code := silence(func() int { return runScan([]string{dir, "--offline"}) }); code != 0 {
		t.Errorf("clean scan exit = %d, want 0", code)
	}
}

func TestRunScan_SecretTripsFailOn(t *testing.T) {
	dir := t.TempDir()
	secret := "sk_live_" + "51H8xLmNoPqRsTuVwXyZ1234abcd"
	os.WriteFile(filepath.Join(dir, "cfg.js"), []byte("const k=\""+secret+"\";\n"), 0o644)
	code := silence(func() int { return runScan([]string{dir, "--offline", "--fail-on", "medium"}) })
	if code != 1 {
		t.Errorf("scan with a secret exit = %d, want 1", code)
	}
}

func TestRunScan_BaselineSuppressesKnown(t *testing.T) {
	dir := t.TempDir()
	secret := "sk_live_" + "51H8xLmNoPqRsTuVwXyZ1234abcd"
	os.WriteFile(filepath.Join(dir, "cfg.js"), []byte("const k=\""+secret+"\";\n"), 0o644)
	base := filepath.Join(dir, "baseline.json")

	// Accept the current state...
	if code := silence(func() int { return runScan([]string{dir, "--offline", "--baseline", base, "--update-baseline"}) }); code != 0 {
		t.Fatalf("update-baseline exit = %d, want 0", code)
	}
	// ...then the same finding no longer fails the build.
	if code := silence(func() int { return runScan([]string{dir, "--offline", "--baseline", base, "--fail-on", "medium"}) }); code != 0 {
		t.Errorf("baselined scan exit = %d, want 0", code)
	}
}

func TestRunScan_BadPath(t *testing.T) {
	if code := silence(func() int { return runScan([]string{"/no/such/dir/xyz"}) }); code != 2 {
		t.Errorf("bad path exit = %d, want 2", code)
	}
}

func TestParseSeverity(t *testing.T) {
	if parseSeverity("critical") <= parseSeverity("low") {
		t.Error("severity ordering is wrong")
	}
	if parseSeverity("nonsense").String() != "INFO" {
		t.Error("unknown severity should fall back to INFO")
	}
}
