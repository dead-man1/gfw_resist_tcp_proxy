// Package version carries the build's identity and the startup banner both
// front-ends print.
//
// For a release, edit the four constants below and nothing else: the banner
// centres its lines and sizes its rules from whatever they contain, so a longer
// version string or a different dedication stays aligned on its own.
package version

import (
	"strings"
	"unicode/utf8"
)

const (
	// Org is the project/author name, shown ahead of the product in window titles.
	Org = "GFW-Knocker"
	// Name is the product name as it appears to users.
	Name = "gfk tunnel"
	// Version is the release. Bump this for a release; that is the only edit a
	// routine version bump needs.
	Version = "v2.0"
	// URL is the project home, shown in the banner.
	URL = "https://github.com/GFW-knocker/gfw_resist_tcp_proxy/"
	// Dedication is the line under the URL.
	Dedication = "in memory of Mahsa-Amini"
)

// rule is the character the banner's top and bottom lines are drawn with.
const rule = "="

// String is the short identity, e.g. "gfk tunnel v2.0". Use it in log attributes
// and anywhere a single line is wanted.
func String() string { return Name + " " + Version }

// Title is the desktop window title, e.g. "GFW-Knocker - gfk tunnel v2.0".
func Title() string { return Org + " - " + String() }

// Banner returns the multi-line startup banner, without a trailing newline:
//
//	====================================================
//	                  gfk tunnel v2.0
//	https://github.com/GFW-knocker/gfw_resist_tcp_proxy/
//	              in memory of Mahsa-Amini
//	====================================================
//
// The rules span the widest line and the rest are centred within it, so the shape
// holds whatever the constants say.
func Banner() string {
	return strings.Join(BannerLines(), "\n")
}

// BannerLines is Banner split into lines, for callers that emit one line at a
// time — the GUI appends each as its own segment in the log pane.
func BannerLines() []string {
	body := []string{String(), URL, Dedication}

	width := 0
	for _, s := range body {
		if w := utf8.RuneCountInString(s); w > width {
			width = w
		}
	}

	lines := make([]string, 0, len(body)+2)
	lines = append(lines, strings.Repeat(rule, width))
	for _, s := range body {
		lines = append(lines, center(s, width))
	}
	return append(lines, strings.Repeat(rule, width))
}

// center pads s with leading spaces so it sits in the middle of width. Rune
// counts, not bytes, so a non-ASCII dedication still lines up. No trailing
// padding: it would only add invisible whitespace to every log line.
func center(s string, width int) string {
	pad := (width - utf8.RuneCountInString(s)) / 2
	if pad <= 0 {
		return s
	}
	return strings.Repeat(" ", pad) + s
}
