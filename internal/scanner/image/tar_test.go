package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func writeTar(w *tar.Writer, name string, body []byte) {
	w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	w.Write(body)
}

func TestExtractPackageDBs_NestedGzippedLayer(t *testing.T) {
	// Inner layer tar (gzipped) holds the dpkg status file.
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	ltw := tar.NewWriter(gz)
	writeTar(ltw, "./var/lib/dpkg/status", []byte("Package: bash\nVersion: 5.0\nStatus: install ok installed\n"))
	writeTar(ltw, "./etc/os-release", []byte("ID=debian\n"))
	ltw.Close()
	gz.Close()

	// Outer image tar holds the layer plus a manifest (which must be ignored).
	var outer bytes.Buffer
	otw := tar.NewWriter(&outer)
	writeTar(otw, "manifest.json", []byte(`[{"Layers":["layer.tar"]}]`))
	writeTar(otw, "abc123/layer.tar", layer.Bytes())
	otw.Close()

	found, err := extractPackageDBs(bytes.NewReader(outer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if found[dpkgPath] == "" {
		t.Fatal("dpkg status not extracted from the gzipped layer")
	}
	pkgs := parseDpkg(found[dpkgPath], distroFromOSRelease(found[osReleasePath]))
	if len(pkgs) != 1 || pkgs[0].Name != "bash" || pkgs[0].Ecosystem != "Debian" {
		t.Errorf("packages parsed wrong: %v", pkgs)
	}
}
