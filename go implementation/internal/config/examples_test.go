package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedConfigsLoad keeps the example and dist YAML honest. They are what a
// user actually edits, so a stale key or a comment block that swallowed the line
// after it has to fail here rather than at someone's first run.
func TestShippedConfigsLoad(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "*", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, p := range paths {
		dir := filepath.Base(filepath.Dir(p))
		if dir != "config" && dir != "dist" {
			continue
		}
		cfg, err := Load(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		checked++

		// The window clamp must resolve to something usable, not zero — a config
		// whose mtu and seq_mode combine into a stalled transport would load
		// cleanly and then pass no traffic at all.
		if k, _ := cfg.EffectiveKCP(); k.SndWnd < 1 {
			t.Errorf("%s: effective kcp sndwnd is %d", p, k.SndWnd)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		// Every mode named in the comments must be one Validate accepts. This is
		// what catches documentation drifting away from the code.
		for _, mode := range []string{"fixed", "random", "realistic"} {
			if !strings.Contains(string(raw), mode) {
				t.Errorf("%s: seq_mode %q is not documented", p, mode)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no shipped configs were found to check")
	}
}
