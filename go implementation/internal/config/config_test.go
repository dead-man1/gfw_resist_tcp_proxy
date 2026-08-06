package config

import (
	"path/filepath"
	"testing"
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
