package logx

import (
	"log/slog"
	"net"
	"testing"
)

func TestParseLevel(t *testing.T) {
	ok := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		" debug ": slog.LevelDebug,
		"warning": slog.LevelWarn,
		"warn":    slog.LevelWarn,
		"error":   slog.LevelError,
		"none":    LevelNone,
		"off":     LevelNone,
	}
	for in, want := range ok {
		got, err := ParseLevel(in)
		if err != nil {
			t.Errorf("ParseLevel(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseLevel("chatty"); err == nil {
		t.Error("ParseLevel should reject an unknown level")
	}
	// LevelNone must silence every real level, or `none` would still log.
	for _, l := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		if l >= LevelNone {
			t.Errorf("level %v is not below LevelNone (%v)", l, LevelNone)
		}
	}
}

func TestMaskAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:443":      "203.0.*.*:443",
		"198.51.100.7:40000":   "198.51.*.*:40000",
		"10.0.0.5":             "10.0.*.*",
		"[2001:db8::1]:45000":  "[2001:db8:*]:45000",
		"2001:db8::1":          "2001:db8:*",
		"vps.example.com:1080": "*:1080", // a name identifies as precisely as an IP
	}
	for in, want := range cases {
		if got := MaskAddr(in); got != want {
			t.Errorf("MaskAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPeerRedactionByLevel(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443}

	SetLevel(slog.LevelDebug)
	if got := Peer(addr).Value.String(); got != "203.0.113.9:443" {
		t.Errorf("debug should print the full address, got %q", got)
	}

	for _, l := range []slog.Level{slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		SetLevel(l)
		if got := Peer(addr).Value.String(); got != "203.0.*.*:443" {
			t.Errorf("level %v should mask, got %q", l, got)
		}
	}

	// At `none` the attr must be empty, so handlers elide it and no IP is printed
	// even if something does manage to log.
	SetLevel(LevelNone)
	if a := Peer(addr); a.Key != "" || !a.Equal(slog.Attr{}) {
		t.Errorf("level none should hide the address entirely, got %v", a)
	}

	SetLevel(slog.LevelInfo) // restore for other tests
	if a := Peer(nil); !a.Equal(slog.Attr{}) {
		t.Errorf("a nil address should produce no attr, got %v", a)
	}
}
