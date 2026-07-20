package sbom

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPurl(t *testing.T) {
	cases := map[Component]string{
		{"lodash", "4.17.11", "npm"}:      "pkg:npm/lodash@4.17.11",
		{"Django", "2.2.0", "PyPI"}:       "pkg:pypi/Django@2.2.0",
		{"gin", "1.6.0", "Go"}:            "pkg:golang/gin@1.6.0",
		{"nokogiri", "1.8.1", "RubyGems"}: "pkg:gem/nokogiri@1.8.1",
		{"serde", "1.0", "crates.io"}:     "pkg:cargo/serde@1.0",
		{"openssl", "1.1", "Alpine:v3.9"}: "pkg:apk/openssl@1.1",
	}
	for c, want := range cases {
		if got := purl(c); got != want {
			t.Errorf("purl(%v) = %q, want %q", c, got, want)
		}
	}
}

func TestWrite_ValidCycloneDXAndDedup(t *testing.T) {
	comps := []Component{
		{"lodash", "4.17.11", "npm"},
		{"lodash", "4.17.11", "npm"}, // duplicate — must collapse
		{"Django", "2.2.0", "PyPI"},
		{"", "x", "npm"}, // empty name — must drop
	}
	var b strings.Builder
	if err := Write(&b, comps, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" {
		t.Errorf("wrong header: %v / %v", doc["bomFormat"], doc["specVersion"])
	}
	if n := len(doc["components"].([]any)); n != 2 {
		t.Errorf("components = %d, want 2 (deduped, empty dropped)", n)
	}
}
