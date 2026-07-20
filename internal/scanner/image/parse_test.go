package image

import "testing"

func TestParseDpkg(t *testing.T) {
	content := "Package: bash\nVersion: 5.0-4\nStatus: install ok installed\n\n" +
		"Package: openssl\nVersion: 1.1.1\nStatus: install ok installed\n\n" +
		"Package: removed-pkg\nVersion: 1.0\nStatus: deinstall ok not-installed\n"
	got := parseDpkg(content, "Debian")
	if len(got) != 2 {
		t.Fatalf("want 2 installed packages, got %d: %v", len(got), got)
	}
	if got[0].Name != "bash" || got[0].Version != "5.0-4" || got[0].Ecosystem != "Debian" {
		t.Errorf("bash parsed wrong: %+v", got[0])
	}
}

func TestParseApk(t *testing.T) {
	content := "P:musl\nV:1.2.2\n\nP:busybox\nV:1.33.1\n"
	got := parseApk(content)
	if len(got) != 2 || got[1].Name != "busybox" || got[1].Version != "1.33.1" || got[1].Ecosystem != "Alpine" {
		t.Errorf("apk parse wrong: %v", got)
	}
}

func TestDistroFromOSRelease(t *testing.T) {
	if d := distroFromOSRelease("ID=ubuntu\nVERSION=20.04\n"); d != "Ubuntu" {
		t.Errorf("want Ubuntu, got %q", d)
	}
	if d := distroFromOSRelease("ID=debian\n"); d != "Debian" {
		t.Errorf("want Debian, got %q", d)
	}
	if d := distroFromOSRelease(""); d != "Debian" {
		t.Errorf("default should be Debian, got %q", d)
	}
}
