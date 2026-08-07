//go:build gui

package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/version"
)

// TestBannerToPane: the log pane must receive the banner verbatim, one line per
// entry, all at a level that renders in the plain foreground colour — the pane
// colours by level, and a banner in warning yellow would read as a problem.
func TestBannerToPane(t *testing.T) {
	type entry struct {
		level slog.Level
		line  string
	}
	var got []entry
	bannerTo(func(l slog.Level, s string) { got = append(got, entry{l, s}) })

	want := version.BannerLines()
	if len(got) != len(want) {
		t.Fatalf("pane got %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].line != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i].line, want[i])
		}
		if got[i].level != slog.LevelInfo {
			t.Errorf("line %d logged at %v; want Info so it is not coloured as a warning", i, got[i].level)
		}
		if strings.Contains(got[i].line, "\n") {
			t.Errorf("line %d contains a newline; the pane needs one segment per line: %q", i, got[i].line)
		}
	}

	// The identity has to be legible in a pasted log.
	if !strings.Contains(strings.Join(want, "\n"), version.Version) {
		t.Errorf("banner does not mention the version %q", version.Version)
	}
}
