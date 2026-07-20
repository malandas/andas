package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/osv"
)

// Package-database and release-metadata paths we look for inside image layers.
const (
	dpkgPath      = "var/lib/dpkg/status"
	apkPath       = "lib/apk/db/installed"
	osReleasePath = "etc/os-release"
	alpineRelPath = "etc/alpine-release"
)

// ScanTarball reads a `docker save` image tarball, extracts the installed OS
// packages, and returns findings for those with known OSV vulnerabilities.
func ScanTarball(path string, timeoutS int) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dbs, err := extractPackageDBs(f)
	if err != nil {
		return nil, err
	}

	var pkgs []pkg
	switch {
	case dbs[dpkgPath] != "":
		// OSV's Debian/Ubuntu ecosystems are versioned, e.g. "Debian:12".
		eco := distroFromOSRelease(dbs[osReleasePath])
		if v := osReleaseVersionID(dbs[osReleasePath]); v != "" {
			eco += ":" + v
		}
		pkgs = parseDpkg(dbs[dpkgPath], eco)
	case dbs[apkPath] != "":
		// OSV's Alpine ecosystem is "Alpine:v3.X" (major.minor of the release).
		pkgs = parseApk(dbs[apkPath])
		if eco := alpineEcosystem(dbs[alpineRelPath]); eco != "" {
			for i := range pkgs {
				pkgs[i].Ecosystem = eco
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "andas: no dpkg or apk package database found in the image")
		return nil, nil
	}

	refs := make([]osv.Ref, len(pkgs))
	for i, p := range pkgs {
		refs[i] = osv.Ref{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem}
	}
	advisories, err := osv.Query(refs, timeoutS)
	if err != nil {
		return nil, fmt.Errorf("OSV lookup: %w", err)
	}

	versionOf := map[string]string{}
	ecoOf := map[string]string{}
	for _, p := range pkgs {
		versionOf[p.Name] = p.Version
		ecoOf[p.Name] = p.Ecosystem
	}
	var out []finding.Finding
	for name, advs := range advisories {
		for _, a := range advs {
			out = append(out, finding.Finding{
				Kind:     finding.KindVuln,
				RuleID:   a.ID,
				Title:    fmt.Sprintf("%s — %s", name, a.Summary),
				File:     fmt.Sprintf("image: %s package", ecoOf[name]),
				Match:    fmt.Sprintf("%s@%s", name, versionOf[name]),
				Severity: a.Severity,
				Fix:      fmt.Sprintf("Rebuild on an updated base image or upgrade %s; see https://osv.dev/vulnerability/%s", name, a.ID),
				Context:  finding.Context{Note: ecoOf[name] + " OS package in the image"},
			})
		}
	}
	fmt.Fprintf(os.Stderr, "andas: %d OS packages inspected in the image\n", len(pkgs))
	return out, nil
}

// extractPackageDBs walks every layer in the image tarball and returns the
// latest content seen for each package-database path (later layers win).
func extractPackageDBs(r io.Reader) (map[string]string, error) {
	found := map[string]string{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Each regular entry might itself be a layer tar (optionally gzipped).
		data, err := io.ReadAll(tr)
		if err != nil {
			continue
		}
		scanLayer(data, found)
	}
	return found, nil
}

// scanLayer treats data as a (possibly gzipped) tar and records any package-DB
// files it contains. Non-tar entries (json manifests, etc.) are ignored.
func scanLayer(data []byte, found map[string]string) {
	rc := io.Reader(bytes.NewReader(data))
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		rc = gz
	}
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return
		}
		name := normalize(hdr.Name)
		if name == dpkgPath || name == apkPath || name == osReleasePath || name == alpineRelPath {
			if b, err := io.ReadAll(tr); err == nil {
				found[name] = string(b)
			}
		}
	}
}

// normalize strips a leading "./" so layer paths match our constants.
func normalize(name string) string {
	for len(name) > 0 && (name[0] == '.' || name[0] == '/') {
		name = name[1:]
	}
	return name
}
