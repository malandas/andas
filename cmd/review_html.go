package cmd

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/malandas/andas/internal/finding"
)

// reviewHTML writes a self-contained, theme-aware, INTERACTIVE review: a verdict,
// the security delta, convention deviations, and every finding grouped by file
// with its confidence, suggested patch, and flow — filterable by severity and
// confidence, searchable, collapsible. No external assets; safe to share.
func reviewHTML(w io.Writer, rev reviewData, delta *deltaResult, scope string) error {
	esc := html.EscapeString
	icon, verdict := reviewVerdict(rev.blocking, rev.total)
	vhex := "#22c55e"
	switch {
	case rev.blocking >= finding.SevHigh:
		vhex = "#ef4444"
	case rev.blocking == finding.SevMedium:
		vhex = "#eab308"
	}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString("<title>andas — security review</title><style>")
	b.WriteString(`
:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--v:` + vhex + `}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--muted:#636c76;--line:#d0d7de}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:36px 20px 60px}
h1{font-size:20px;margin:0}.sub{color:var(--muted);font-size:13px;margin-top:4px}
.verdict{display:flex;gap:16px;align-items:center;background:var(--card);border:1px solid var(--line);border-left:5px solid var(--v);border-radius:12px;padding:20px 22px;margin:22px 0}
.verdict .i{font-size:34px}.verdict .t{font-weight:700;font-size:17px;color:var(--v)}.verdict .d{color:var(--muted);font-size:13.5px;margin-top:3px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:16px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat .n{font-size:22px;font-weight:700}.stat .l{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.4px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);margin:30px 0 10px;border-bottom:1px solid var(--line);padding-bottom:7px}
.bar{position:sticky;top:0;background:var(--bg);padding:12px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center;z-index:5;border-bottom:1px solid var(--line)}
.bar button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:20px;padding:5px 12px;font-size:12.5px;cursor:pointer}
.bar button.on{background:var(--v);color:#fff;border-color:var(--v)}
.bar input{flex:1;min-width:140px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font-size:13px}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0;overflow:hidden}
summary{cursor:pointer;padding:12px 16px;font-family:ui-monospace,Menlo,monospace;font-size:13.5px;font-weight:600}
.f{padding:10px 16px 14px;border-top:1px solid var(--line)}
.pill{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:20px;color:#fff}
.badge{font-size:11px;padding:1px 7px;border-radius:20px;border:1px solid var(--line);color:var(--muted);margin-left:6px}
.badge.ok{color:#22c55e;border-color:#22c55e}.badge.warn{color:#8b949e}
.loc{color:var(--muted);font-size:12px;font-family:ui-monospace,Menlo,monospace}
pre{background:rgba(127,127,127,.08);border-radius:8px;padding:8px 10px;overflow-x:auto;font-size:12.5px;margin:8px 0}
.diff .del{color:#ef4444}.diff .add{color:#22c55e}
.fix{font-size:13px;margin-top:6px}.fix b{color:var(--v)}
.alert{background:var(--card);border:1px solid var(--line);border-left:4px solid #ef4444;border-radius:8px;padding:10px 14px;margin:8px 0}
.good{border-left-color:#22c55e}.foot{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:16px}
.hidden{display:none}
`)
	b.WriteString("</style></head><body><div class=\"wrap\">")

	b.WriteString(`<h1>andas · security code review</h1><div class="sub">reviewing ` + esc(scope) + `</div>`)
	b.WriteString(`<div class="verdict"><div class="i">` + icon + `</div><div><div class="t">` + esc(verdict) + `</div><div class="d">` + esc(reviewTLDR(rev)) + `</div></div></div>`)

	// Stats
	b.WriteString(`<div class="grid">`)
	stat := func(n int, l string) {
		b.WriteString(fmt.Sprintf(`<div class="stat"><div class="n">%d</div><div class="l">%s</div></div>`, n, l))
	}
	stat(rev.counts[finding.SevCritical], "critical")
	stat(rev.counts[finding.SevHigh], "high")
	stat(rev.counts[finding.SevMedium], "medium")
	stat(rev.tentative, "tentative")
	if delta != nil {
		stat(len(delta.NewNoAuth), "new no-auth")
		stat(len(delta.NewSecrets), "new secrets")
	}
	b.WriteString(`</div>`)

	// Security delta
	if delta != nil && !delta.empty() {
		b.WriteString(`<h2>Security delta vs base</h2>`)
		al := func(cls, s string) { b.WriteString(`<div class="alert ` + cls + `">` + s + `</div>`) }
		if n := len(delta.NewNoAuth); n > 0 {
			al("", fmt.Sprintf("▲ <b>%d new unauthenticated endpoint(s)</b>", n))
		}
		if n := len(delta.WeakenedAuth); n > 0 {
			al("", fmt.Sprintf("▲ <b>%d endpoint(s) lost their auth check</b>", n))
		}
		if n := len(delta.NewSecrets); n > 0 {
			al("", fmt.Sprintf("▲ <b>%d new secret(s) introduced</b>", n))
		}
		if delta.ResolvedCount > 0 {
			al("good", fmt.Sprintf("▼ %d pre-existing issue(s) resolved", delta.ResolvedCount))
		}
	}

	// Convention deviations
	if len(rev.conventions) > 0 {
		b.WriteString(`<h2>Convention deviations</h2>`)
		for _, d := range rev.conventions {
			b.WriteString(`<div class="alert"><b>` + esc(d.route.Method+" "+d.route.Path) + `</b><div class="loc">` + esc(d.convention) + `</div></div>`)
		}
	}

	// Filter bar
	b.WriteString(`<h2>Findings</h2>`)
	b.WriteString(`<div class="bar">` +
		`<button class="on" data-f="all" onclick="flt(this)">All</button>` +
		`<button data-f="critical" onclick="flt(this)">Critical</button>` +
		`<button data-f="high" onclick="flt(this)">High</button>` +
		`<button data-f="confirmed" onclick="flt(this)">Confirmed only</button>` +
		`<input id="q" placeholder="search…" oninput="srch(this.value)"></div>`)

	if rev.total == 0 {
		b.WriteString(`<p class="sub">No security findings. 🎉</p>`)
	}
	for _, rf := range rev.files {
		b.WriteString(`<details open><summary>` + esc(rf.path) + fmt.Sprintf(` <span class="badge">%d</span></summary>`, len(rf.findings)))
		for _, f := range rf.findings {
			rr := f.RealRisk()
			conf := f.Confidence()
			attrs := fmt.Sprintf(`data-sev="%s" data-conf="%s" data-txt="%s"`,
				strings.ToLower(rr.String()), conf.String(),
				strings.ToLower(esc(f.Title+" "+f.File)))
			b.WriteString(`<div class="f" ` + attrs + `>`)
			b.WriteString(`<span class="pill" style="background:` + riskHex(rr) + `">` + esc(rr.String()) + `</span> `)
			b.WriteString(`<b>` + esc(f.Title) + `</b>`)
			switch conf {
			case finding.Confirmed:
				b.WriteString(`<span class="badge ok">✓ confirmed</span>`)
			case finding.Tentative:
				b.WriteString(`<span class="badge warn">? tentative</span>`)
			}
			b.WriteString(`<div class="loc">` + esc(shortFile(f.File)) + ":" + itoa(f.Line))
			if f.Context.CWE != "" {
				b.WriteString(" · " + esc(f.Context.CWE))
			}
			b.WriteString(`</div>`)
			if m := strings.TrimSpace(f.Match); m != "" {
				b.WriteString(`<pre>` + esc(m) + `</pre>`)
			}
			if fixed, ok := suggestPatch(f.RuleID, strings.TrimSpace(f.Match)); ok && f.Kind == finding.KindCode {
				b.WriteString(`<pre class="diff"><span class="del">- ` + esc(strings.TrimSpace(f.Match)) + `</span>` + "\n" + `<span class="add">+ ` + esc(strings.TrimSpace(fixed)) + `</span></pre>`)
			} else if f.Fix != "" {
				b.WriteString(`<div class="fix"><b>→</b> ` + esc(f.Fix) + `</div>`)
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(`</details>`)
	}

	b.WriteString(`<div class="foot">Generated by andas — real security risk, not noise. Read-only.</div>`)
	b.WriteString(`<script>
var sev="all";
function flt(btn){document.querySelectorAll('.bar button').forEach(function(b){b.classList.remove('on')});btn.classList.add('on');sev=btn.dataset.f;apply()}
function srch(v){window._q=v.toLowerCase();apply()}
function apply(){var q=window._q||"";document.querySelectorAll('.f').forEach(function(el){
 var okSev = sev=='all' || (sev=='confirmed'? el.dataset.conf=='confirmed' : el.dataset.sev==sev);
 var okQ = !q || el.dataset.txt.indexOf(q)>=0;
 el.classList.toggle('hidden', !(okSev&&okQ));
});
document.querySelectorAll('details').forEach(function(d){
 var any=d.querySelectorAll('.f:not(.hidden)').length; d.style.display=any?'':'none';
})}
</script></div></body></html>`)

	_, err := io.WriteString(w, b.String())
	return err
}
