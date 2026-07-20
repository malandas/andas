package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTmp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func find(refs []pkgRef, name string) (pkgRef, bool) {
	for _, r := range refs {
		if r.Name == name {
			return r, true
		}
	}
	return pkgRef{}, false
}

func TestParseRequirements(t *testing.T) {
	p := writeTmp(t, "requirements.txt", "# comment\nDjango==2.2.0\nrequests>=2.0  # unpinned, skip\nFlask==0.12.2\n")
	refs := parseRequirements(p)
	if r, ok := find(refs, "Django"); !ok || r.Version != "2.2.0" || r.Ecosystem != "PyPI" {
		t.Errorf("Django parsed wrong: %+v", r)
	}
	if _, ok := find(refs, "requests"); ok {
		t.Error("unpinned requests should be skipped")
	}
	if len(refs) != 2 {
		t.Errorf("expected 2 pinned deps, got %d", len(refs))
	}
}

func TestParseGoMod(t *testing.T) {
	p := writeTmp(t, "go.mod", "module x\n\ngo 1.20\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n\tgopkg.in/yaml.v2 v2.2.2 // indirect\n)\n")
	refs := parseGoMod(p)
	if r, ok := find(refs, "github.com/gin-gonic/gin"); !ok || r.Version != "1.6.0" || r.Ecosystem != "Go" {
		t.Errorf("gin parsed wrong: %+v", r)
	}
	if r, ok := find(refs, "gopkg.in/yaml.v2"); !ok || r.Version != "2.2.2" {
		t.Errorf("indirect dep not parsed: %+v", r)
	}
}

func TestParseCargoLock(t *testing.T) {
	p := writeTmp(t, "Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"tokio\"\nversion = \"0.2.1\"\n")
	refs := parseCargoLock(p)
	if r, ok := find(refs, "tokio"); !ok || r.Version != "0.2.1" || r.Ecosystem != "crates.io" {
		t.Errorf("tokio parsed wrong: %+v", r)
	}
	if len(refs) != 2 {
		t.Errorf("expected 2 crates, got %d", len(refs))
	}
}

func TestParseGemfileLock(t *testing.T) {
	p := writeTmp(t, "Gemfile.lock", "GEM\n  specs:\n    rails (5.2.0)\n    nokogiri (1.8.1)\n")
	refs := parseGemfileLock(p)
	if r, ok := find(refs, "rails"); !ok || r.Version != "5.2.0" || r.Ecosystem != "RubyGems" {
		t.Errorf("rails parsed wrong: %+v", r)
	}
}

func TestParseComposerLock(t *testing.T) {
	p := writeTmp(t, "composer.lock", `{"packages":[{"name":"monolog/monolog","version":"1.0.0"},{"name":"symfony/http","version":"v4.0.1"}]}`)
	refs := parseComposerLock(p)
	if r, ok := find(refs, "symfony/http"); !ok || r.Version != "4.0.1" || r.Ecosystem != "Packagist" {
		t.Errorf("symfony parsed wrong (v prefix should strip): %+v", r)
	}
}
