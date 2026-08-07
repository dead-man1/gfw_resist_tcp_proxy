package version

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestString(t *testing.T) {
	if got := String(); got != Name+" "+Version {
		t.Errorf("String() = %q", got)
	}
	if !strings.HasPrefix(Version, "v") {
		t.Errorf("Version = %q, want a leading v", Version)
	}
}

// TestTitle pins the desktop window title: "GFW-Knocker - gfk tunnel v2.0".
func TestTitle(t *testing.T) {
	if got, want := Title(), Org+" - "+String(); got != want {
		t.Errorf("Title() = %q, want %q", got, want)
	}
	for _, part := range []string{Org, Name, Version} {
		if !strings.Contains(Title(), part) {
			t.Errorf("Title() = %q, missing %q", Title(), part)
		}
	}
}

// TestBannerShape: the banner must be a closed box — rules top and bottom, every
// line inside no wider than the rule.
func TestBannerShape(t *testing.T) {
	lines := BannerLines()
	if len(lines) != 5 {
		t.Fatalf("banner has %d lines, want 5: %q", len(lines), lines)
	}

	width := utf8.RuneCountInString(lines[0])
	if lines[0] != strings.Repeat(rule, width) || lines[len(lines)-1] != lines[0] {
		t.Errorf("first and last line should both be a full rule, got %q and %q", lines[0], lines[len(lines)-1])
	}
	for i, l := range lines {
		if w := utf8.RuneCountInString(l); w > width {
			t.Errorf("line %d is %d wide, past the %d-wide rule: %q", i, w, width, l)
		}
		if strings.HasSuffix(l, " ") {
			t.Errorf("line %d has trailing whitespace: %q", i, l)
		}
	}

	for _, want := range []string{String(), URL, Dedication} {
		if !strings.Contains(Banner(), want) {
			t.Errorf("banner is missing %q", want)
		}
	}
	if strings.HasSuffix(Banner(), "\n") {
		t.Error("Banner should not end in a newline; callers add their own")
	}
}

// TestBannerRecentresItself is the maintenance promise: a version bump must not
// require touching the layout. Feeding the centring a longer identity has to keep
// the box square.
func TestBannerRecentresItself(t *testing.T) {
	lines := BannerLines()
	width := utf8.RuneCountInString(lines[0])

	// The widest body line is the URL today, so it should sit flush and unindented.
	if lines[2] != URL {
		t.Errorf("the widest line should not be indented, got %q", lines[2])
	}

	// Centring puts each shorter line within one character of the middle.
	for i, s := range []string{String(), Dedication} {
		line := lines[1+i*2]
		lead := utf8.RuneCountInString(line) - utf8.RuneCountInString(strings.TrimLeft(line, " "))
		want := (width - utf8.RuneCountInString(s)) / 2
		if lead != want {
			t.Errorf("%q indented by %d, want %d", s, lead, want)
		}
	}

	// A body line wider than the rule cannot happen today, but centring must not
	// panic or produce negative padding if the constants change.
	if got := center("a string much longer than the width", 5); got != "a string much longer than the width" {
		t.Errorf("center should pass through an over-long string, got %q", got)
	}
}
