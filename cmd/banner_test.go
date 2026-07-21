package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestBanner_PlainHasNoEscapes(t *testing.T) {
	art := staticArt(colorNone)
	if strings.Contains(art, "\033") {
		t.Error("colorNone art must contain no ANSI escapes (safe for pipes/CI)")
	}
	// All six wordmark rows must be present.
	for _, row := range bannerLines {
		if !strings.Contains(art, row) {
			t.Errorf("plain art is missing a wordmark row: %q", row)
		}
	}
}

func TestBanner_TrueColorHasGradient(t *testing.T) {
	art := staticArt(colorTrue)
	if !strings.Contains(art, "\033[38;2;") {
		t.Error("truecolour art should use 24-bit SGR sequences")
	}
	// The gradient must span from the cyan start to the green end colour.
	if !strings.Contains(art, "38;2;34;211;238") {
		t.Error("truecolour art missing the cyan start colour")
	}
	if !strings.Contains(art, "38;2;74;222;128") {
		t.Error("truecolour art missing the green end colour")
	}
}

func TestBanner_256Fallback(t *testing.T) {
	if !strings.Contains(staticArt(color256), "\033[38;5;") {
		t.Error("256-colour art should use indexed SGR sequences")
	}
}

func TestColorMode_NoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if m := colorMode(os.Stderr); m != colorNone {
		t.Errorf("NO_COLOR set: colorMode = %d, want colorNone", m)
	}
}

func TestAnimAllowed_DisabledInCI(t *testing.T) {
	t.Setenv("CI", "true")
	if animAllowed(os.Stderr) {
		t.Error("animation must be disabled when CI is set")
	}
}

func TestTo256_InRange(t *testing.T) {
	for _, c := range [][3]int{{34, 211, 238}, {74, 222, 128}, {0, 0, 0}, {255, 255, 255}} {
		if got := to256(c[0], c[1], c[2]); got < 16 || got > 231 {
			t.Errorf("to256(%v) = %d, outside the 16-231 colour cube", c, got)
		}
	}
}
