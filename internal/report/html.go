package report

import (
	"html/template"
	"io"

	"github.com/malandas/andas/internal/finding"
)

// HTML writes a self-contained, styled report — no external assets — suitable
// for sharing or archiving from CI. Findings are ordered by real risk and the
// header leads with the number that matters: real risks vs. filtered noise.
func HTML(w io.Writer, findings []finding.Finding, target string) error {
	rows := rank(findings)

	type item struct {
		Risk      string
		RiskClass string
		Title     string
		Loc       string
		Match     string
		Note      string
		Symbols   string
		Fix       string
		Promoted  bool
		Demoted   bool
	}
	var items []item
	var real, noise int
	counts := map[string]int{}
	for _, r := range rows {
		f := r.f
		counts[r.risk.String()]++
		if r.risk >= finding.SevMedium {
			real++
		} else {
			noise++
		}
		loc := f.File
		if f.Line > 0 {
			loc = f.File + ":" + itoa(f.Line)
		}
		it := item{
			Risk:      r.risk.String(),
			RiskClass: "sev-" + r.risk.String(),
			Title:     f.Title,
			Loc:       loc,
			Match:     f.Match,
			Note:      f.Context.Note,
			Fix:       f.Fix,
		}
		if len(f.Context.Symbols) > 0 {
			it.Symbols = join(f.Context.Symbols, ", ")
		}
		switch f.Kind {
		case finding.KindSecret:
			it.Promoted = f.Context.Validated && f.Context.Live
			it.Demoted = f.Context.Validated && !f.Context.Live
		case finding.KindVuln:
			it.Promoted = f.Context.Reachable != nil && *f.Context.Reachable
			it.Demoted = f.Context.Reachable != nil && !*f.Context.Reachable
		}
		items = append(items, it)
	}

	data := struct {
		Target string
		Real   int
		Noise  int
		Total  int
		Counts map[string]int
		Items  []item
	}{target, real, noise, len(rows), counts, items}

	return htmlTemplate.Execute(w, data)
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>andas — real-risk report</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--line:#21262d;--fg:#e6edf3;--dim:#8b949e;
    --crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff;--info:#6e7681;--ok:#3fb950;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
  .wrap{max-width:880px;margin:0 auto;padding:40px 20px 80px}
  h1{font-size:24px;margin:0 0 4px;letter-spacing:-.02em}
  h1 b{color:var(--ok)}
  .sub{color:var(--dim);margin:0 0 28px;font-size:13px;word-break:break-all}
  .summary{display:flex;gap:14px;margin-bottom:8px;flex-wrap:wrap}
  .stat{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);
    border-radius:12px;padding:16px 18px}
  .stat .n{font-size:30px;font-weight:700;letter-spacing:-.03em}
  .stat .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
  .stat.real .n{color:var(--crit)} .stat.noise .n{color:var(--ok)}
  .bar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin:22px 0 34px;background:var(--line)}
  .bar span{display:block}
  .card{background:var(--card);border:1px solid var(--line);border-left-width:4px;
    border-radius:10px;padding:14px 16px;margin-bottom:12px}
  .card .top{display:flex;align-items:center;gap:10px;margin-bottom:6px}
  .badge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px;letter-spacing:.04em}
  .title{font-weight:600}
  .loc{color:var(--dim);font-size:12.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
    margin:2px 0;word-break:break-all}
  .match{color:var(--dim);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
  .ctx{margin-top:8px;font-size:13px}
  .ctx .promoted{color:var(--crit);font-weight:600}
  .ctx .demoted{color:var(--dim)}
  .ctx .sym{color:var(--med)}
  .fix{margin-top:8px;font-size:13px;color:var(--ok);padding-left:14px;border-left:2px solid var(--ok)}
  .sev-CRITICAL{border-left-color:var(--crit)} .sev-CRITICAL .badge{background:var(--crit);color:#0d1117}
  .sev-HIGH{border-left-color:var(--high)} .sev-HIGH .badge{background:var(--high);color:#0d1117}
  .sev-MEDIUM{border-left-color:var(--med)} .sev-MEDIUM .badge{background:var(--med);color:#0d1117}
  .sev-LOW{border-left-color:var(--low)} .sev-LOW .badge{background:var(--low);color:#0d1117}
  .sev-INFO{border-left-color:var(--info)} .sev-INFO .badge{background:var(--info);color:#0d1117}
  .foot{color:var(--dim);font-size:12px;text-align:center;margin-top:40px}
  .empty{text-align:center;color:var(--ok);padding:60px 0;font-size:18px}
</style></head><body><div class="wrap">
<h1><b>andas</b> — real-risk report</h1>
<p class="sub">target: {{.Target}}</p>
<div class="summary">
  <div class="stat real"><div class="n">{{.Real}}</div><div class="l">real risks</div></div>
  <div class="stat noise"><div class="n">{{.Noise}}</div><div class="l">filtered as noise</div></div>
  <div class="stat"><div class="n">{{.Total}}</div><div class="l">total findings</div></div>
</div>
<div class="bar">
  {{with index .Counts "CRITICAL"}}<span style="flex:{{.}};background:var(--crit)"></span>{{end}}
  {{with index .Counts "HIGH"}}<span style="flex:{{.}};background:var(--high)"></span>{{end}}
  {{with index .Counts "MEDIUM"}}<span style="flex:{{.}};background:var(--med)"></span>{{end}}
  {{with index .Counts "LOW"}}<span style="flex:{{.}};background:var(--low)"></span>{{end}}
  {{with index .Counts "INFO"}}<span style="flex:{{.}};background:var(--info)"></span>{{end}}
</div>
{{if .Items}}{{range .Items}}
<div class="card {{.RiskClass}}">
  <div class="top"><span class="badge">{{.Risk}}</span><span class="title">{{.Title}}</span></div>
  <div class="loc">{{.Loc}}</div>
  <div class="match">{{.Match}}</div>
  {{if .Note}}<div class="ctx"><span class="{{if .Promoted}}promoted{{else if .Demoted}}demoted{{end}}">{{if .Promoted}}▲ {{else if .Demoted}}▼ {{end}}{{.Note}}</span></div>{{end}}
  {{if .Symbols}}<div class="ctx sym">↳ your code uses: {{.Symbols}}</div>{{end}}
  {{if and .Fix .Promoted}}<div class="fix">→ {{.Fix}}</div>{{end}}
</div>
{{end}}{{else}}<div class="empty">✓ no findings — clean scan</div>{{end}}
<p class="foot">generated by andas · real risk = detection + context</p>
</div></body></html>`))

// small helpers to avoid extra imports in this file's hot path
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func join(s []string, sep string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += sep
		}
		out += v
	}
	return out
}
