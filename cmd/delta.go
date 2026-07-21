package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/deps"
	"github.com/malandas/andas/internal/scanner/iac"
	"github.com/malandas/andas/internal/scanner/sast"
	"github.com/malandas/andas/internal/scanner/secrets"
	"github.com/malandas/andas/internal/scanner/surface"
)

// computeSecurityDelta materialises the base ref, analyses the whole project on
// both sides, and returns how the posture moved. Best-effort: returns ok=false
// if the base can't be checked out (e.g. a shallow clone or a dirty worktree).
func computeSecurityDelta(root, ref string, opts scanner.Options, headFindings []finding.Finding) (deltaResult, bool) {
	baseDir, cleanup, err := baseWorktree(root, ref)
	if err != nil {
		return deltaResult{}, false
	}
	defer cleanup()

	headRoutes, _ := surface.Map(root, opts.IgnorePaths)
	baseIgnore := scanner.LoadIgnore(baseDir)
	baseRoutes, err := surface.Map(baseDir, baseIgnore)
	if err != nil {
		return deltaResult{}, false
	}
	baseOpts := opts
	baseOpts.IgnorePaths = baseIgnore
	baseAll, err := runScanners([]scanner.Scanner{secrets.New(), deps.New(), sast.New(), iac.New()}, baseDir, baseOpts)
	if err != nil {
		return deltaResult{}, false
	}
	return diffPosture(baseRoutes, headRoutes,
		kindOf(baseAll, finding.KindSecret), kindOf(headFindings, finding.KindSecret),
		baseAll, headFindings), true
}

func kindOf(fs []finding.Finding, k finding.Kind) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

// deltaResult is how a change moved the project's SECURITY POSTURE — the one
// thing a PR author actually needs to know: did this make us more exposed?
type deltaResult struct {
	NewEndpoints  []surface.Route // endpoints that did not exist on the base
	NewNoAuth     []surface.Route // subset: new endpoints with no visible auth
	WeakenedAuth  []surface.Route // existed before, was authed, now is not
	NewSecrets    []finding.Finding
	ResolvedCount int // real-risk findings the base had that are now gone
}

// routeKey identifies an endpoint across base/head regardless of line moves.
func routeKey(r surface.Route) string { return strings.ToUpper(r.Method) + " " + r.Path }

// diffPosture computes the security delta from the base vs head surface and
// secrets. Pure and deterministic — no git, no I/O — so it is fully testable.
func diffPosture(baseRoutes, headRoutes []surface.Route, baseSecrets, headSecrets, baseFindings, headFindings []finding.Finding) deltaResult {
	baseAuth := map[string]bool{} // route key -> was it authed on the base
	for _, r := range baseRoutes {
		baseAuth[routeKey(r)] = r.Auth
	}
	var d deltaResult
	seen := map[string]bool{}
	for _, r := range headRoutes {
		k := routeKey(r)
		if seen[k] {
			continue
		}
		seen[k] = true
		wasAuthed, existed := baseAuth[k]
		switch {
		case !existed:
			d.NewEndpoints = append(d.NewEndpoints, r)
			if !r.Auth {
				d.NewNoAuth = append(d.NewNoAuth, r)
			}
		case wasAuthed && !r.Auth:
			d.WeakenedAuth = append(d.WeakenedAuth, r)
		}
	}

	// New secrets: real (non-placeholder) secret values present on head but not base.
	baseSec := map[string]bool{}
	for _, f := range baseSecrets {
		baseSec[f.RuleID+"|"+f.Match] = true
	}
	for _, f := range headSecrets {
		if f.Context.Placeholder {
			continue
		}
		if !baseSec[f.RuleID+"|"+f.Match] {
			d.NewSecrets = append(d.NewSecrets, f)
		}
	}

	// Net resolved: real-risk findings that the base had and head no longer does.
	headKeys := map[string]bool{}
	for _, f := range headFindings {
		headKeys[findingKey(f)] = true
	}
	for _, f := range baseFindings {
		if f.RealRisk() >= finding.SevMedium && !headKeys[findingKey(f)] {
			d.ResolvedCount++
		}
	}
	return d
}

func findingKey(f finding.Finding) string {
	return f.RuleID + "|" + shortFile(f.File) + "|" + strings.TrimSpace(f.Match)
}

// worse reports whether the delta increased exposure (used to sharpen the verdict).
func (d deltaResult) worse() bool {
	return len(d.NewNoAuth) > 0 || len(d.WeakenedAuth) > 0 || len(d.NewSecrets) > 0
}

func (d deltaResult) empty() bool {
	return len(d.NewEndpoints) == 0 && len(d.WeakenedAuth) == 0 && len(d.NewSecrets) == 0 && d.ResolvedCount == 0
}

// baseWorktree materialises the base ref into a throwaway git worktree so the
// base version of the whole project can be analysed. Read-only w.r.t. the user's
// working tree; the worktree is removed by the returned cleanup func.
func baseWorktree(root, ref string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "andas-base-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() {
		exec.Command("git", "-C", root, "worktree", "remove", "--force", dir).Run()
		os.RemoveAll(dir)
	}
	if out, e := exec.Command("git", "-C", root, "worktree", "add", "--detach", dir, ref).CombinedOutput(); e != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("git worktree add: %v (%s)", e, strings.TrimSpace(string(out)))
	}
	return dir, cleanup, nil
}

// printDelta renders the SECURITY DELTA section of a review.
func printDelta(w io.Writer, d deltaResult, base string, color bool) {
	p := painter(color)
	rule(w, p, "SECURITY DELTA vs "+base)
	if d.empty() {
		fmt.Fprintln(w, "    "+p(cGrn, "no change to the security posture."))
		fmt.Fprintln(w)
		return
	}
	line := func(icon, code, label string, n int) {
		if n > 0 {
			fmt.Fprintf(w, "    %s %s\n", p(code, icon), p(code+cBold, fmt.Sprintf("%d %s", n, label)))
		}
	}
	line("▲", cRed, "new unauthenticated endpoint(s)", len(d.NewNoAuth))
	line("▲", cRed, "endpoint(s) that lost their auth check", len(d.WeakenedAuth))
	line("▲", cRed, "new secret(s) introduced", len(d.NewSecrets))
	line("△", cYel, "new endpoint(s) total", len(d.NewEndpoints))
	line("▼", cGrn, "pre-existing issue(s) resolved", d.ResolvedCount)

	show := func(title string, rs []surface.Route) {
		if len(rs) == 0 {
			return
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Path < rs[j].Path })
		fmt.Fprintf(w, "      %s\n", p(cGray, title))
		for i, r := range rs {
			if i == 5 {
				fmt.Fprintf(w, "        %s\n", p(cGray, fmt.Sprintf("… and %d more", len(rs)-5)))
				break
			}
			fmt.Fprintf(w, "        %s %s\n", p(cBold, pad(r.Method, 6)), r.Path)
		}
	}
	show("new & unauthenticated:", d.NewNoAuth)
	show("lost auth:", d.WeakenedAuth)
	fmt.Fprintln(w)
}
