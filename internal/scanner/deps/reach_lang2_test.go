package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRubyReach_ExplicitRequire(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.rb"), []byte("require 'nokogiri'\n"), 0o644)
	refs := []pkgRef{{Name: "nokogiri"}, {Name: "rack"}}
	got := rubyReach(dir, nil, refs)
	if !got["nokogiri"] {
		t.Error("nokogiri is required and must be reachable")
	}
	if got["rack"] {
		t.Error("rack is not required and must not be reachable")
	}
}

func TestRubyReach_BundlerAutoloadKeepsAllReachable(t *testing.T) {
	dir := t.TempDir()
	// Bundler.require auto-loads every gem — we must not demote anything.
	os.WriteFile(filepath.Join(dir, "app.rb"), []byte("Bundler.require(*Rails.groups)\n"), 0o644)
	refs := []pkgRef{{Name: "nokogiri"}, {Name: "rack"}}
	got := rubyReach(dir, nil, refs)
	if !got["nokogiri"] || !got["rack"] {
		t.Errorf("under Bundler.require all gems must stay reachable, got %v", got)
	}
}

func TestRustReach_UnderscoreMapping(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.rs"), []byte("use serde_json::Value;\nfn main() {}\n"), 0o644)
	refs := []pkgRef{{Name: "serde-json"}, {Name: "tokio"}} // Cargo name uses hyphen
	got := rustReach(dir, nil, refs)
	if !got["serde-json"] {
		t.Error("serde-json should be reachable via `use serde_json`")
	}
	if got["tokio"] {
		t.Error("tokio is not used and must not be reachable")
	}
}

func TestPhpReach_NamespaceFromLock(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(
		`{"packages":[{"name":"monolog/monolog","autoload":{"psr-4":{"Monolog\\":"src/"}}},`+
			`{"name":"guzzlehttp/guzzle","autoload":{"psr-4":{"GuzzleHttp\\":"src/"}}}]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php\nuse Monolog\\Logger;\n"), 0o644)
	refs := []pkgRef{{Name: "monolog/monolog"}, {Name: "guzzlehttp/guzzle"}}
	got := phpReach(dir, nil, refs)
	if !got["monolog/monolog"] {
		t.Error("monolog should be reachable via `use Monolog\\...`")
	}
	if got["guzzlehttp/guzzle"] {
		t.Error("guzzle namespace is not referenced and must not be reachable")
	}
}
