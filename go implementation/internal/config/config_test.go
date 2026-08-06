package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/carrier"
)

// TestExampleConfigsValidate ensures the shipped example configs load and pass
// validation — in particular that the server example (empty vps_ip) is accepted
// while the client example (vps_ip set) is too.
func TestExampleConfigsValidate(t *testing.T) {
	for _, name := range []string{"server.example.yaml", "client.example.yaml"} {
		p := filepath.Join("..", "..", "config", name)
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("%s: load: %v", name, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: validate: %v", name, err)
		}
	}
}

// TestServerAllowsEmptyVPSIP / client requires it.
func TestVPSIPRequirement(t *testing.T) {
	base := Default()
	base.Auth.Key = "k"
	base.Carrier.ServerPort, base.Carrier.ClientPort, base.Carrier.MTU = 45000, 40000, 1400

	srv := base
	srv.Mode = ModeServer
	srv.Server.BackendIP = "127.0.0.1"
	srv.Carrier.VPSIP = ""
	if err := srv.Validate(); err != nil {
		t.Errorf("server with empty vps_ip should validate, got: %v", err)
	}
	srv.Carrier.ClientPort = 0 // server ignores client_port; must not be required
	if err := srv.Validate(); err != nil {
		t.Errorf("server should not require client_port, got: %v", err)
	}

	cli := base
	cli.Mode = ModeClient
	cli.Client.Forwards = []Forward{{Proto: "tcp", Listen: "127.0.0.1:14000", TargetPort: 443}}
	cli.Carrier.VPSIP = ""
	if err := cli.Validate(); err == nil {
		t.Errorf("client with empty vps_ip should fail validation")
	}
}

// validServer is a minimal server config that passes Validate, for tests that
// then break exactly one field.
func validServer() Config {
	c := Default()
	c.Mode = ModeServer
	c.Auth.Key = "k"
	c.Server.BackendIP = "127.0.0.1"
	return c
}

// TestPacketShapeValidation: a config that would put a SYN or RST on the wire, or
// name a flag/seq mode that does not exist, must be refused at load time rather
// than silently ignored.
func TestPacketShapeValidation(t *testing.T) {
	bad := map[string][]string{
		"syn":            {"ack", "syn"},
		"rst":            {"ack", "rst"},
		"unknown flag":   {"ack", "ece"},
		"nothing chosen": {" "},
	}
	for name, flags := range bad {
		c := validServer()
		c.Carrier.TCPFlags = flags
		if err := c.Validate(); err == nil {
			t.Errorf("tcp_flags %v (%s) should be refused", flags, name)
		}
	}
	for _, flags := range [][]string{nil, {"ack"}, {"ack", "push"}, {"ack", "psh", "urg", "fin"}} {
		c := validServer()
		c.Carrier.TCPFlags = flags
		if err := c.Validate(); err != nil {
			t.Errorf("tcp_flags %v should be accepted, got %v", flags, err)
		}
	}

	for _, mode := range []string{"", "fixed", "realistic"} {
		c := validServer()
		c.Carrier.SeqMode = mode
		if err := c.Validate(); err != nil {
			t.Errorf("seq_mode %q should be accepted, got %v", mode, err)
		}
	}
	c := validServer()
	c.Carrier.SeqMode = "random"
	if err := c.Validate(); err == nil {
		t.Error("seq_mode random should be refused")
	}
}

// attrMap flattens EffectiveAttrs into a lookup, failing if the pairs are
// malformed (slog would silently render a dangling key as "!BADKEY").
func attrMap(t *testing.T, attrs []any) map[string]string {
	t.Helper()
	if len(attrs)%2 != 0 {
		t.Fatalf("EffectiveAttrs returned %d items, want key/value pairs", len(attrs))
	}
	m := map[string]string{}
	for i := 0; i < len(attrs); i += 2 {
		k, ok := attrs[i].(string)
		if !ok {
			t.Fatalf("attr key %d is %T, want string", i, attrs[i])
		}
		if _, dup := m[k]; dup {
			t.Errorf("duplicate attr key %q", k)
		}
		m[k] = fmt.Sprint(attrs[i+1])
	}
	return m
}

// TestEffectiveAttrs: this line is how a GUI user confirms that settings with no
// widget were honoured, so it must cover them, report resolved values rather than
// raw strings, and never carry the shared key.
func TestEffectiveAttrs(t *testing.T) {
	c := validServer()
	c.Carrier.Interface = "eth1"
	c.Carrier.TCPFlags = nil // omitted in the file => the ack+psh default
	c.Carrier.SeqMode = ""   // ditto => fixed
	c.KCP.SndWnd, c.KCP.FECData, c.KCP.FECParity = 512, 10, 3
	c.Auth.Key = "a-secret-that-must-not-be-logged"

	m := attrMap(t, c.EffectiveAttrs())
	for _, k := range []string{"transport", "interface", "mtu", "server_port",
		"server_port_span", "tcp_flags", "seq_mode", "log_level"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing attr %q", k)
		}
	}
	if m["tcp_flags"] != "ack+psh" {
		t.Errorf("tcp_flags = %q, want the resolved default ack+psh", m["tcp_flags"])
	}
	if m["seq_mode"] != string(carrier.SeqFixed) {
		t.Errorf("seq_mode = %q, want the resolved default fixed", m["seq_mode"])
	}
	if m["interface"] != "eth1" || m["kcp_sndwnd"] != "512" || m["kcp_fec"] != "10/3" {
		t.Errorf("file-only settings not reported: %v", m)
	}
	for k, v := range m {
		if strings.Contains(v, "secret-that-must-not-be-logged") {
			t.Errorf("attr %q leaks auth.key", k)
		}
	}

	// The tuning block reported must match the selected transport.
	if _, ok := m["quic_max_idle_timeout"]; ok {
		t.Error("a kcp config should not report quic knobs")
	}
	c.Transport = TransportQUIC
	m = attrMap(t, c.EffectiveAttrs())
	if _, ok := m["quic_max_idle_timeout"]; !ok {
		t.Error("a quic config should report quic knobs")
	}
	if _, ok := m["kcp_sndwnd"]; ok {
		t.Error("a quic config should not report kcp knobs")
	}

	// Client mode reports the client-side timers instead of the server section.
	cli := Default()
	cli.Auth.Key = "k"
	cli.Carrier.VPSIP = "203.0.113.10"
	cli.Client.Forwards = []Forward{{Proto: "tcp", Listen: "127.0.0.1:14000", TargetPort: 443}}
	if err := cli.Validate(); err != nil {
		t.Fatal(err)
	}
	m = attrMap(t, cli.EffectiveAttrs())
	for _, k := range []string{"client_port", "client_port_span", "keepalive_s", "reconnect_s"} {
		if _, ok := m[k]; !ok {
			t.Errorf("client mode should report %q", k)
		}
	}
	if _, ok := m["backend_ip"]; ok {
		t.Error("client mode should not report the server section")
	}
}

// TestLogLevelValidation: a typo in log_level used to silently mean info, which
// could leave a server logging client IPs when the operator asked for none.
func TestLogLevelValidation(t *testing.T) {
	for _, lvl := range []string{"", "none", "error", "warn", "warning", "info", "debug", "DEBUG"} {
		c := validServer()
		c.LogLevel = lvl
		if err := c.Validate(); err != nil {
			t.Errorf("log_level %q should be accepted, got %v", lvl, err)
		}
	}
	c := validServer()
	c.LogLevel = "nono"
	if err := c.Validate(); err == nil {
		t.Error("a misspelled log_level should be refused, not silently treated as info")
	}
}
