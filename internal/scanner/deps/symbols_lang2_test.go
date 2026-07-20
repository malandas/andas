package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRubySymbols(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.rb"),
		[]byte("doc = Nokogiri::XML(x)\nNokogiri.parse(y)\n"), 0o644)
	got := rubySymbols(dir, nil, []pkgRef{{Name: "nokogiri"}})
	if !has(got["nokogiri"], "XML") || !has(got["nokogiri"], "parse") {
		t.Errorf("nokogiri symbols = %v, want XML+parse", got["nokogiri"])
	}
}

func TestRubyConstant(t *testing.T) {
	cases := map[string]string{"nokogiri": "Nokogiri", "active-record": "ActiveRecord", "rails": "Rails", "json": "JSON"}
	for in, want := range cases {
		if got := rubyConstant(in); got != want {
			t.Errorf("rubyConstant(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRustSymbols(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.rs"),
		[]byte("let v = serde_json::from_str(x);\nserde_json::to_string(y);\n"), 0o644)
	got := rustSymbols(dir, nil, []pkgRef{{Name: "serde-json"}})
	if !has(got["serde-json"], "from_str") || !has(got["serde-json"], "to_string") {
		t.Errorf("serde-json symbols = %v", got["serde-json"])
	}
}

func TestPhpSymbols(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(`{"packages":[{"name":"monolog/monolog","autoload":{"psr-4":{"Monolog\\":"src/"}}}]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "index.php"),
		[]byte("<?php\nuse Monolog\\Logger;\nuse Monolog\\Handler\\StreamHandler;\n"), 0o644)
	got := phpSymbols(dir, nil, []pkgRef{{Name: "monolog/monolog"}})
	if !has(got["monolog/monolog"], "Logger") || !has(got["monolog/monolog"], "StreamHandler") {
		t.Errorf("monolog symbols = %v, want Logger+StreamHandler", got["monolog/monolog"])
	}
}
