package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// bannerLines is the andas wordmark (ANSI Shadow style). It is shown only on the
// welcome/help screen — never during a scan, whose output is parsed by CI and
// JSON consumers where a banner would be the very noise andas fights.
var bannerLines = []string{
	` █████╗ ███╗   ██╗██████╗  █████╗ ███████╗`,
	`██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝`,
	`███████║██╔██╗ ██║██║  ██║███████║███████╗`,
	`██╔══██║██║╚██╗██║██║  ██║██╔══██║╚════██║`,
	`██║  ██║██║ ╚████║██████╔╝██║  ██║███████║`,
	`╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚══════╝`,
}

const (
	tagline = "sift real security risk from the noise"

	// Gradient endpoints: cyan → green (a security-tool palette).
	gradR0, gradG0, gradB0 = 34, 211, 238 // #22d3ee cyan
	gradR1, gradG1, gradB1 = 74, 222, 128 // #4ade80 green

	// band is the width, in cells, of the bright shimmer that sweeps the wordmark.
	band = 16

	// indent insets the whole banner from the left edge so it doesn't sit flush
	// against the terminal border. Kept small so it never wraps on narrow
	// terminals (true centring would need the terminal width, which we can't read
	// without leaving the standard library).
	indent = "    "
)

// colour capability, from least to most capable.
const (
	colorNone = iota // NO_COLOR, or output is piped/redirected
	colorBasic       // a TTY, but only the 8/16-colour palette is assumed
	color256         // 256-colour palette
	colorTrue        // 24-bit truecolour
)

// renderBanner draws the wordmark to w: an animated gradient shimmer on a
// capable terminal, a static gradient/green otherwise, always followed by the
// tagline and version.
func renderBanner(w *os.File) {
	mode := colorMode(w)
	if mode >= color256 && animAllowed(w) {
		animateBanner(w, mode)
	} else {
		fmt.Fprint(w, staticArt(mode))
	}
	fmt.Fprint(w, taglineLine(mode))
}

// bannerWidth is the display width (in cells) of the widest art line.
func bannerWidth() int {
	m := 0
	for _, l := range bannerLines {
		if n := len([]rune(l)); n > m {
			m = n
		}
	}
	return m
}

// staticArt renders the wordmark with a horizontal gradient (256/truecolour) or
// a flat bold green (basic), with no animation.
func staticArt(mode int) string {
	var b strings.Builder
	b.WriteByte('\n')
	if mode == colorNone {
		for _, l := range bannerLines {
			b.WriteString(indent + l + "\n")
		}
		return b.String()
	}
	if mode == colorBasic {
		for _, l := range bannerLines {
			b.WriteString(indent + "\033[1;32m" + l + "\033[0m\n")
		}
		return b.String()
	}
	w := bannerWidth()
	for _, l := range bannerLines {
		b.WriteString(indent + renderArtLine(l, w, 1<<30, mode) + "\n") // sweep far off → no shimmer
	}
	return b.String()
}

// animateBanner plays a bright shimmer sweeping left-to-right across the
// gradient wordmark, redrawing in place, then settles on the clean gradient.
func animateBanner(w *os.File, mode int) {
	n := len(bannerLines)
	width := bannerWidth()
	const step = 3
	const frame = 28 * time.Millisecond

	fmt.Fprint(w, "\033[?25l\n") // hide cursor, leading blank line
	first := true
	for sweep := -band; sweep <= width+band; sweep += step {
		if !first {
			fmt.Fprintf(w, "\033[%dA", n) // back to the top of the art
		}
		first = false
		for _, l := range bannerLines {
			fmt.Fprint(w, "\r\033[K"+indent+renderArtLine(l, width, sweep, mode)+"\n")
		}
		time.Sleep(frame)
	}
	fmt.Fprint(w, "\033[?25h") // show cursor
}

// renderArtLine colours one art line: each glyph gets its gradient colour by
// column, brightened toward white when it falls under the shimmer band centred
// at `sweep`. Spaces are left uncoloured so the escape stream stays lean.
func renderArtLine(line string, width, sweep, mode int) string {
	runes := []rune(line)
	var b strings.Builder
	b.WriteString("\033[1m")
	for col, r := range runes {
		if r == ' ' {
			b.WriteByte(' ')
			continue
		}
		t := 0.0
		if width > 1 {
			t = float64(col) / float64(width-1)
		}
		cr := lerp(gradR0, gradR1, t)
		cg := lerp(gradG0, gradG1, t)
		cb := lerp(gradB0, gradB1, t)

		if d := abs(col - sweep); d < band/2 {
			f := (1 - float64(d)/float64(band/2)) * 0.85
			cr += int(float64(255-cr) * f)
			cg += int(float64(255-cg) * f)
			cb += int(float64(255-cb) * f)
		}
		b.WriteString(colorEsc(cr, cg, cb, mode))
		b.WriteRune(r)
	}
	b.WriteString("\033[0m")
	return b.String()
}

// taglineLine renders the tagline (left) and version (right-aligned to the art
// width), dimmed when colour is available.
func taglineLine(mode int) string {
	ver := "v" + version
	w := bannerWidth()
	pad := w - len(tagline) - len(ver)
	if pad < 1 {
		pad = 1
	}
	line := indent + tagline + strings.Repeat(" ", pad) + ver
	if mode == colorNone {
		return line + "\n\n"
	}
	return "\033[2m" + line + "\033[0m\n\n"
}

// --- colour helpers -------------------------------------------------------

func lerp(a, b int, t float64) int { return a + int(float64(b-a)*t) }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// colorEsc returns the SGR escape selecting (r,g,b) for the given mode.
func colorEsc(r, g, b, mode int) string {
	if mode == colorTrue {
		return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
	}
	return fmt.Sprintf("\033[38;5;%dm", to256(r, g, b))
}

// to256 maps an RGB triple to the nearest xterm-256 colour-cube index.
func to256(r, g, b int) int {
	q := func(v int) int { return (v*5 + 127) / 255 }
	return 16 + 36*q(r) + 6*q(g) + q(b)
}

// colorMode reports the richest colour the output stream supports.
func colorMode(w *os.File) int {
	if os.Getenv("NO_COLOR") != "" || !isTTY(w) {
		return colorNone
	}
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit") {
		return colorTrue
	}
	if term := os.Getenv("TERM"); strings.Contains(term, "256") {
		return color256
	}
	return colorBasic
}

// animAllowed gates the shimmer: an interactive terminal, motion not disabled,
// and not a CI environment.
func animAllowed(w *os.File) bool {
	if !isTTY(w) || os.Getenv("ANDAS_NO_ANIM") != "" || os.Getenv("CI") != "" {
		return false
	}
	return true
}

func isTTY(w *os.File) bool {
	fi, err := w.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// banner returns the static wordmark string (no animation) — kept for callers
// and tests that want the plain rendering.
func banner() string { return staticArt(colorMode(os.Stderr)) + taglineLine(colorMode(os.Stderr)) }
