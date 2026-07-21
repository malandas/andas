package cmd

import (
	"fmt"
	"os"
)

// bannerArt is the andas wordmark shown on the welcome/help screen. It is
// deliberately NOT printed during a scan — that output is parsed by CI and JSON
// consumers, so a banner there would be noise (the very thing andas fights).
const bannerArt = `
                          _
     __ _  _ __    __| |  __ _  ___
    / _` + "`" + ` || '_ \  / _` + "`" + ` | / _` + "`" + ` |/ __|
   | (_| || | | || (_| || (_| |\__ \
    \__,_||_| |_| \__,_| \__,_||___/`

// banner returns the andas logo, tagline, and version. Colour is applied only
// when writing to a real terminal (and never when NO_COLOR is set).
func banner() string {
	const (
		reset = "\033[0m"
		green = "\033[32m"
		bold  = "\033[1m"
		dim   = "\033[2m"
	)
	art, tagline, ver := bannerArt, "  sift real security risk from the noise", "  v"+version
	if colorEnabled() {
		art = green + bold + bannerArt + reset
		tagline = dim + tagline + reset
		ver = dim + ver + reset
	}
	return fmt.Sprintf("%s\n%s   %s\n", art, tagline, ver)
}

// colorEnabled reports whether the banner's stream (stderr) is an interactive
// terminal and NO_COLOR is unset — so it stays plain when piped or in CI logs.
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
