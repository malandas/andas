package report

import (
	"fmt"
	"io"

	"github.com/malandas/andas/internal/finding"
)

// Markdown writes a compact report suited to a pull-request comment. andas only
// produces the text — posting it (if at all) is left to your CI, keeping andas
// strictly read-only.
func Markdown(w io.Writer, findings []finding.Finding) error {
	rows := rank(findings)
	var real, noise int
	for _, r := range rows {
		if r.risk >= finding.SevMedium {
			real++
		} else {
			noise++
		}
	}

	fmt.Fprintln(w, "## 🛡️ andas security report")
	fmt.Fprintln(w)
	if len(rows) == 0 {
		fmt.Fprintln(w, "✅ No findings — clean scan.")
		return nil
	}
	fmt.Fprintf(w, "**%d real risk(s)** · %d filtered as noise · %d total\n\n", real, noise, len(rows))

	if ap := AttackPath(findings); len(ap) > 0 {
		fmt.Fprintln(w, "### ⚔ Attack path")
		for _, line := range ap {
			fmt.Fprintf(w, "- %s\n", line)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "| Risk | Finding | Location | Fix |")
	fmt.Fprintln(w, "|------|---------|----------|-----|")
	for _, r := range rows {
		if r.risk < finding.SevMedium {
			continue // keep the comment focused on what matters
		}
		fmt.Fprintf(w, "| %s | %s | `%s` | %s |\n",
			r.risk.String(), mdEscape(r.f.Title), mdLoc(r.f), mdEscape(r.f.Fix))
	}
	if noise > 0 {
		fmt.Fprintf(w, "\n<sub>%d finding(s) verified harmless and filtered out.</sub>\n", noise)
	}
	return nil
}

func mdLoc(f finding.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// mdEscape neutralises the pipe so it can't break the table layout.
func mdEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '|' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}
