package cmd

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// auditHTML writes a self-contained, theme-aware executive report. No external
// assets — safe to email or drop on an internal wiki.
func auditHTML(w io.Writer, r auditResult) error {
	esc := html.EscapeString
	gradeHex := map[byte]string{'A': "#22c55e", 'B': "#06b6d4", 'C': "#eab308", 'D': "#f97316", 'F': "#ef4444"}[r.Grade[0]]

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString("<title>andas — security audit: " + esc(r.Root) + "</title><style>")
	b.WriteString(`
:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--accent:` + gradeHex + `}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--muted:#636c76;--line:#d0d7de}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px}
h1{font-size:20px;margin:0}.sub{color:var(--muted);font-size:13px;margin-top:4px}
.hero{display:flex;align-items:center;gap:24px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;margin:24px 0}
.badge{width:104px;height:104px;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:52px;font-weight:800;color:#fff;background:var(--accent);flex:none}
.score{font-size:28px;font-weight:700}.verdict{color:var(--muted);margin-top:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:20px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat .n{font-size:24px;font-weight:700}.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
.item{background:var(--card);border:1px solid var(--line);border-left-width:3px;border-radius:8px;padding:12px 16px;margin:8px 0}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;color:#fff}
.loc{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:4px}
.fix{margin-top:8px;font-size:13px}.fix b{color:var(--accent)}
.chain{padding:8px 0;border-bottom:1px dashed var(--line);font-size:14px}
.foot{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:16px}
.crit{color:#ef4444}.high{color:#f97316}.med{color:#eab308}.low{color:var(--muted)}
`)
	b.WriteString("</style></head><body><div class=\"wrap\">")

	// Header + hero
	b.WriteString(`<h1>andas · security audit</h1>`)
	b.WriteString(`<div class="sub">target: ` + esc(r.Root) + ` · ` + dur(r.Elapsed) + ` · authorised assessment only</div>`)
	b.WriteString(`<div class="hero"><div class="badge">` + esc(r.Grade) + `</div><div>`)
	b.WriteString(fmt.Sprintf(`<div class="score">%d/100</div>`, r.Score))
	b.WriteString(`<div class="verdict">` + esc(gradeVerdict(r.Grade)) + `</div></div></div>`)

	// Stat grid
	b.WriteString(`<div class="grid">`)
	stat := func(n int, label, cls string) {
		b.WriteString(fmt.Sprintf(`<div class="stat"><div class="n %s">%d</div><div class="l">%s</div></div>`, cls, n, label))
	}
	stat(r.Counts["CRITICAL"], "critical", "crit")
	stat(r.Counts["HIGH"], "high", "high")
	stat(r.Counts["MEDIUM"], "medium", "med")
	stat(r.Endpoints, "endpoints", "")
	stat(r.NoAuth, "no-auth", "")
	stat(r.Exploitable, "exploitable", "high")
	b.WriteString(`</div>`)

	// Top priorities
	if items := prioritise(r); len(items) > 0 {
		b.WriteString(`<h2>Top priorities</h2>`)
		for _, it := range items {
			hex := riskHex(it.risk)
			b.WriteString(`<div class="item" style="border-left-color:` + hex + `">`)
			b.WriteString(`<span class="pill" style="background:` + hex + `">` + esc(it.risk.String()) + `</span> <b>` + esc(it.what) + `</b>`)
			if it.where != "" {
				b.WriteString(`<div class="loc">` + esc(it.where) + `</div>`)
			}
			b.WriteString(`<div class="fix"><b>→</b> ` + esc(it.how) + `</div></div>`)
		}
	}

	// Exploit candidates
	if len(r.Candidates) > 0 {
		b.WriteString(`<h2>Exploit candidates</h2>`)
		for _, t := range r.Candidates {
			b.WriteString(`<div class="item" style="border-left-color:#f97316">`)
			auth := ""
			if !t.route.Auth {
				auth = ` · <span class="high">NO-AUTH</span>`
			}
			b.WriteString(`<b>` + esc(t.route.Method+" "+t.route.Path) + `</b>` + auth)
			if len(t.sinks) > 0 {
				s := t.sinks[0]
				b.WriteString(`<div class="loc">→ reaches ` + esc(s.Title) + ` (` + esc(s.Context.CWE) + `) · ` + esc(s.File) + ":" + itoa(s.Line) + `</div>`)
			}
			b.WriteString(`</div>`)
		}
	}

	// Attack chains
	if len(r.Chains) > 0 {
		b.WriteString(`<h2>Attack chains</h2>`)
		for _, c := range r.Chains {
			b.WriteString(`<div class="chain">▸ ` + esc(c) + `</div>`)
		}
	}

	b.WriteString(`<div class="foot">secrets · dependencies · SAST (C#/JS/TS/Py/Go/Ruby/PHP) · IaC · surface · exploit-linking<br>`)
	b.WriteString(`Generated by andas — sift real security risk from the noise. Read-only.</div>`)
	b.WriteString(`</div></body></html>`)

	_, err := io.WriteString(w, b.String())
	return err
}

func riskHex(s finding.Severity) string {
	switch s {
	case finding.SevCritical:
		return "#ef4444"
	case finding.SevHigh:
		return "#f97316"
	case finding.SevMedium:
		return "#eab308"
	default:
		return "#8b949e"
	}
}
