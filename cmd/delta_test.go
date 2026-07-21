package cmd

import (
	"testing"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner/surface"
)

func r(method, path string, auth bool) surface.Route {
	return surface.Route{Method: method, Path: path, Auth: auth}
}

func TestDiffPosture_NewAndWeakened(t *testing.T) {
	base := []surface.Route{
		r("GET", "/a", true),
		r("GET", "/b", true),
	}
	head := []surface.Route{
		r("GET", "/a", true),          // unchanged
		r("GET", "/b", false),         // WEAKENED: lost auth
		r("POST", "/c", false),        // NEW, no-auth
		r("GET", "/d", true),          // NEW, authed
	}
	d := diffPosture(base, head, nil, nil, nil, nil)
	if len(d.NewEndpoints) != 2 {
		t.Errorf("new endpoints = %d, want 2", len(d.NewEndpoints))
	}
	if len(d.NewNoAuth) != 1 || d.NewNoAuth[0].Path != "/c" {
		t.Errorf("new no-auth wrong: %+v", d.NewNoAuth)
	}
	if len(d.WeakenedAuth) != 1 || d.WeakenedAuth[0].Path != "/b" {
		t.Errorf("weakened wrong: %+v", d.WeakenedAuth)
	}
	if !d.worse() {
		t.Error("delta should report the posture got worse")
	}
}

func TestDiffPosture_NewSecretIgnoresPlaceholder(t *testing.T) {
	sec := func(id, match string, ph bool) finding.Finding {
		return finding.Finding{Kind: finding.KindSecret, RuleID: id, Match: match, Context: finding.Context{Placeholder: ph}}
	}
	base := []finding.Finding{sec("stripe", "aaa", false)}
	head := []finding.Finding{
		sec("stripe", "aaa", false),        // pre-existing
		sec("github", "ghp_new", false),    // NEW real secret
		sec("google", "YOUR_KEY", true),    // NEW but placeholder → ignored
	}
	d := diffPosture(nil, nil, base, head, nil, nil)
	if len(d.NewSecrets) != 1 || d.NewSecrets[0].RuleID != "github" {
		t.Errorf("new secrets wrong: %+v", d.NewSecrets)
	}
}

func TestDiffPosture_CleanChange(t *testing.T) {
	base := []surface.Route{r("GET", "/a", true)}
	head := []surface.Route{r("GET", "/a", true)}
	d := diffPosture(base, head, nil, nil, nil, nil)
	if !d.empty() || d.worse() {
		t.Errorf("identical posture should be empty/not-worse: %+v", d)
	}
}
