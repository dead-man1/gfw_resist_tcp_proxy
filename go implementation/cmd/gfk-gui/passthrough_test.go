//go:build gui

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
)

// hiddenSettingsYAML sets every knob the window has NO widget for to a value
// that differs from config.Default(), so a field lost anywhere between the file
// and Connect shows up as a concrete mismatch below.
const hiddenSettingsYAML = `
mode: client
transport: quic
carrier:
  vps_ip: "203.0.113.10"
  server_port: 46000
  server_port_span: 3
  client_port: 41000
  client_port_span: 2
  interface: "Ethernet 7"
  mtu: 1300
  tcp_flags: [ack, psh, urg]
  seq_mode: realistic
firewall:
  manage: "no"
auth:
  key: "a-long-shared-secret-for-the-test"
kcp:
  nodelay: 0
  interval: 25
  resend: 3
  nc: 0
  sndwnd: 512
  rcvwnd: 1024
  fec_data: 10
  fec_parity: 3
  stream_buffer: 8388608
  session_buffer: 33554432
quic:
  keepalive_period: 7
  max_idle_timeout: 21
client:
  socks5_listen: "127.0.0.1:1080"
  forwards:
    - {proto: tcp, listen: "127.0.0.1:14000", target_port: 2096}
  keepalive_seconds: 9
  reconnect_seconds: 5
log_level: debug
`

// loadYAML runs the production parse used by both Load and the startup
// auto-load, so this test breaks if that path stops layering over the defaults.
func loadYAML(t *testing.T, raw string) config.Config {
	t.Helper()
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fixture should be valid: %v", err)
	}
	return cfg
}

// formFor returns the field contents the window would show for cfg — i.e. what
// applyConfig writes into the widgets.
func formFor(cfg config.Config) formValues {
	return formValues{
		transport: string(cfg.Transport),
		vps:       cfg.Carrier.VPSIP,
		key:       cfg.Auth.Key,
		srvPort:   strconv.Itoa(int(cfg.Carrier.ServerPort)),
		srvSpan:   strconv.Itoa(cfg.Carrier.ServerPortSpan),
		cliPort:   strconv.Itoa(int(cfg.Carrier.ClientPort)),
		cliSpan:   strconv.Itoa(cfg.Carrier.ClientPortSpan),
		mtu:       strconv.Itoa(cfg.Carrier.MTU),
		socks:     cfg.Client.Socks5Listen,
		forwards:  forwardsToText(cfg.Client.Forwards),
		firewall:  cfg.Firewall.Manage != config.FirewallNo,
	}
}

// TestHiddenSettingsSurviveFormEdit is the guarantee: load a config, change the
// one field a user typically changes (the VPS IP), and everything the window
// cannot show must reach Connect exactly as the file specified.
func TestHiddenSettingsSurviveFormEdit(t *testing.T) {
	loaded := loadYAML(t, hiddenSettingsYAML)

	form := formFor(loaded)
	form.vps = "198.51.100.42" // the user edits only this

	got, err := overlayForm(loaded, form)
	if err != nil {
		t.Fatalf("overlayForm: %v", err)
	}

	if got.Carrier.VPSIP != "198.51.100.42" {
		t.Errorf("the edited field should win: vps_ip = %q", got.Carrier.VPSIP)
	}

	// Every setting with no widget must be byte-for-byte what the file said.
	checks := []struct {
		name      string
		got, want any
	}{
		{"carrier.interface", got.Carrier.Interface, loaded.Carrier.Interface},
		{"carrier.tcp_flags", got.Carrier.TCPFlags, loaded.Carrier.TCPFlags},
		{"carrier.seq_mode", got.Carrier.SeqMode, loaded.Carrier.SeqMode},
		{"kcp", got.KCP, loaded.KCP},
		{"quic", got.QUIC, loaded.QUIC},
		{"client.keepalive_seconds", got.Client.KeepAliveSeconds, loaded.Client.KeepAliveSeconds},
		{"client.reconnect_seconds", got.Client.ReconnectSeconds, loaded.Client.ReconnectSeconds},
		{"log_level", got.LogLevel, loaded.LogLevel},
		{"server", got.Server, loaded.Server},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s was not carried through: got %v, want %v", c.name, c.got, c.want)
		}
	}

	// And the widget-backed ones must still round-trip (this is where
	// server_port_span used to be dropped).
	if got.Carrier.ServerPortSpan != 3 {
		t.Errorf("server_port_span = %d, want 3 from the file", got.Carrier.ServerPortSpan)
	}
	if got.Carrier.ClientPortSpan != 2 {
		t.Errorf("client_port_span = %d, want 2 from the file", got.Carrier.ClientPortSpan)
	}
	if got.Carrier.ServerPort != 46000 || got.Carrier.ClientPort != 41000 {
		t.Errorf("ports = %d/%d, want 46000/41000", got.Carrier.ServerPort, got.Carrier.ClientPort)
	}
	if got.Carrier.MTU != 1300 {
		t.Errorf("mtu = %d, want 1300", got.Carrier.MTU)
	}
	if got.Transport != config.TransportQUIC {
		t.Errorf("transport = %q, want quic", got.Transport)
	}
}

// TestNoConfigLoadedUsesDefaults: with no file loaded the base is Default(), so a
// user who just types a VPS IP and a key still gets a valid, working config.
func TestNoConfigLoadedUsesDefaults(t *testing.T) {
	base := config.Default()
	form := formFor(base)
	form.vps = "198.51.100.42"
	form.key = "another-long-shared-secret"
	form.socks = "127.0.0.1:1080"

	got, err := overlayForm(base, form)
	if err != nil {
		t.Fatalf("overlayForm: %v", err)
	}
	if !reflect.DeepEqual(got.KCP, base.KCP) {
		t.Errorf("kcp defaults changed: %v", got.KCP)
	}
	if !reflect.DeepEqual(got.Carrier.TCPFlags, base.Carrier.TCPFlags) {
		t.Errorf("tcp_flags defaults changed: %v", got.Carrier.TCPFlags)
	}
	if got.Carrier.SeqMode != base.Carrier.SeqMode {
		t.Errorf("seq_mode = %q, want the default %q", got.Carrier.SeqMode, base.Carrier.SeqMode)
	}
}

// TestFormEditsBeatTheFile: the fields that DO have widgets must override the
// loaded file, or editing the form would appear to do nothing.
func TestFormEditsBeatTheFile(t *testing.T) {
	loaded := loadYAML(t, hiddenSettingsYAML)
	form := formFor(loaded)
	form.transport = string(config.TransportKCP)
	form.srvPort = "45500"
	form.srvSpan = "6"
	form.cliPort = "40500"
	form.cliSpan = "1"
	form.mtu = "1200"
	form.firewall = true

	got, err := overlayForm(loaded, form)
	if err != nil {
		t.Fatalf("overlayForm: %v", err)
	}
	if got.Transport != config.TransportKCP {
		t.Errorf("transport = %q, want the form's kcp", got.Transport)
	}
	if got.Carrier.ServerPort != 45500 || got.Carrier.ServerPortSpan != 6 {
		t.Errorf("server port/span = %d/%d, want 45500/6", got.Carrier.ServerPort, got.Carrier.ServerPortSpan)
	}
	if got.Carrier.ClientPort != 40500 || got.Carrier.ClientPortSpan != 1 {
		t.Errorf("client port/span = %d/%d, want 40500/1", got.Carrier.ClientPort, got.Carrier.ClientPortSpan)
	}
	if got.Carrier.MTU != 1200 {
		t.Errorf("mtu = %d, want 1200", got.Carrier.MTU)
	}
	if got.Firewall.Manage != config.FirewallYes {
		t.Errorf("firewall.manage = %q, want yes from the checkbox", got.Firewall.Manage)
	}
	// Switching the transport in the form must not disturb either tuning block.
	if !reflect.DeepEqual(got.KCP, loaded.KCP) || !reflect.DeepEqual(got.QUIC, loaded.QUIC) {
		t.Error("transport switch should not alter the kcp/quic settings from the file")
	}
}

// TestAutoConfigPaths: the startup auto-load must look beside the executable
// first (how the release zip is laid out), then in the working directory.
func TestAutoConfigPaths(t *testing.T) {
	paths := autoConfigPaths()
	if len(paths) == 0 {
		t.Fatal("no candidate paths")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable path on this platform")
	}
	if want := filepath.Join(filepath.Dir(exe), "client.yaml"); paths[0] != want {
		t.Errorf("first candidate = %q, want %q (next to the binary)", paths[0], want)
	}
	last := paths[len(paths)-1]
	if last != "gfk.yaml" {
		t.Errorf("last candidate = %q, want the bare working-directory name", last)
	}
	for _, p := range paths {
		base := filepath.Base(p)
		if base != "client.yaml" && base != "gfk.yaml" {
			t.Errorf("unexpected candidate %q: the GUI is client-only", p)
		}
	}
}

// TestAutoLoadedFileFeedsTheSameOverlay: a config found at startup must reach
// Connect through the same path a dialog-loaded one does.
func TestAutoLoadedFileFeedsTheSameOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(path, []byte(hiddenSettingsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	got, err := overlayForm(cfg, formFor(cfg))
	if err != nil {
		t.Fatalf("overlayForm: %v", err)
	}
	if got.Carrier.SeqMode != "realistic" || got.KCP.FECData != 10 || got.Carrier.Interface != "Ethernet 7" {
		t.Errorf("auto-loaded file-only settings did not survive: seq_mode=%q fec=%d interface=%q",
			got.Carrier.SeqMode, got.KCP.FECData, got.Carrier.Interface)
	}
}

// TestGarbageInFormFallsBackToFile: a blanked or nonsense numeric field must fall
// back to the loaded value rather than silently becoming zero.
func TestGarbageInFormFallsBackToFile(t *testing.T) {
	loaded := loadYAML(t, hiddenSettingsYAML)
	form := formFor(loaded)
	form.srvPort = ""
	form.srvSpan = "abc"
	form.cliPort = "0"
	form.mtu = "not-a-number"

	got, err := overlayForm(loaded, form)
	if err != nil {
		t.Fatalf("overlayForm: %v", err)
	}
	if got.Carrier.ServerPort != 46000 {
		t.Errorf("blank server_port should keep the file's 46000, got %d", got.Carrier.ServerPort)
	}
	if got.Carrier.ServerPortSpan != 3 {
		t.Errorf("bad server_port_span should keep the file's 3, got %d", got.Carrier.ServerPortSpan)
	}
	if got.Carrier.ClientPort != 41000 {
		t.Errorf("zero client_port should keep the file's 41000, got %d", got.Carrier.ClientPort)
	}
	if got.Carrier.MTU != 1300 {
		t.Errorf("bad mtu should keep the file's 1300, got %d", got.Carrier.MTU)
	}
}
