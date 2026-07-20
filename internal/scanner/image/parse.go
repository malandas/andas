// Package image scans a container image tarball (`docker save -o img.tar …`)
// for vulnerable OS packages. It reads the image's layers, finds the distro's
// package database, and cross-references every installed package against OSV —
// the same real-risk engine andas uses for application dependencies, extended
// down to the base image.
package image

import (
	"strings"
)

// pkg is an installed OS package resolved to its OSV ecosystem.
type pkg struct {
	Name      string
	Version   string
	Ecosystem string // "Debian", "Ubuntu", "Alpine"
}

// parseDpkg reads a Debian/Ubuntu /var/lib/dpkg/status file: paragraphs
// separated by blank lines, each with Package/Version/Status fields.
func parseDpkg(content, ecosystem string) []pkg {
	var out []pkg
	var name, version string
	installed := true
	flush := func() {
		if name != "" && version != "" && installed {
			out = append(out, pkg{Name: name, Version: version, Ecosystem: ecosystem})
		}
		name, version, installed = "", "", true
	}
	for _, line := range strings.Split(content, "\n") {
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(line[len("Package: "):])
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(line[len("Version: "):])
		case strings.HasPrefix(line, "Status: "):
			installed = strings.Contains(line, "installed") && !strings.Contains(line, "not-installed")
		}
	}
	flush()
	return out
}

// parseApk reads an Alpine /lib/apk/db/installed file: records separated by
// blank lines, "P:" package and "V:" version fields.
func parseApk(content string) []pkg {
	var out []pkg
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, pkg{Name: name, Version: version, Ecosystem: "Alpine"})
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(content, "\n") {
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "P:"):
			name = strings.TrimSpace(line[2:])
		case strings.HasPrefix(line, "V:"):
			version = strings.TrimSpace(line[2:])
		}
	}
	flush()
	return out
}

// distroFromOSRelease maps /etc/os-release to the OSV ecosystem for dpkg-based
// images. Alpine is detected separately (it has an apk DB, not dpkg).
func distroFromOSRelease(content string) string {
	id := ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimSpace(line[3:]), `"`)
		}
	}
	switch id {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	default:
		return "Debian" // reasonable default for a dpkg-based image
	}
}

// osReleaseVersionID returns VERSION_ID (e.g. "12" for Debian, "20.04" for
// Ubuntu) so we can build OSV's versioned ecosystem string.
func osReleaseVersionID(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "VERSION_ID=") {
			return strings.Trim(strings.TrimSpace(line[len("VERSION_ID="):]), `"`)
		}
	}
	return ""
}

// alpineEcosystem turns an /etc/alpine-release value like "3.12.0" into the OSV
// ecosystem "Alpine:v3.12". Returns "" if the release can't be read.
func alpineEcosystem(release string) string {
	release = strings.TrimSpace(release)
	if release == "" {
		return ""
	}
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return ""
	}
	return "Alpine:v" + parts[0] + "." + parts[1]
}
