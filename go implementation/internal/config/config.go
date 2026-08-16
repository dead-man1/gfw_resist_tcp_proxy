// Package config defines the on-disk YAML configuration for gfk and the
// runtime defaults. One struct serves both client and server; the `mode`
// field selects which half of the config is active.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/carrier"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/logx"
)

// Mode is client or server.
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// Transport selects the reliability layer that runs on top of the carrier.
type Transport string

const (
	TransportKCP  Transport = "kcp"
	TransportQUIC Transport = "quic"
)

// FirewallPolicy controls whether gfk touches the OS firewall to suppress
// kernel RSTs for the carrier port.
type FirewallPolicy string

const (
	// FirewallAsk prompts the user once at startup (interactive TTY only).
	FirewallAsk FirewallPolicy = "ask"
	// FirewallYes applies the rules without prompting (use for services).
	FirewallYes FirewallPolicy = "yes"
	// FirewallNo never touches the firewall; the user manages RST suppression.
	FirewallNo FirewallPolicy = "no"
)

// Config is the whole file.
type Config struct {
	Mode      Mode      `yaml:"mode"`
	Transport Transport `yaml:"transport"`

	Carrier  CarrierConfig  `yaml:"carrier"`
	Firewall FirewallConfig `yaml:"firewall"`
	Auth     AuthConfig     `yaml:"auth"`
	KCP      KCPConfig      `yaml:"kcp"`
	QUIC     QUICConfig     `yaml:"quic"`

	Client ClientConfig `yaml:"client"`
	Server ServerConfig `yaml:"server"`

	// LogLevel is one of none|error|warn|info|debug (see logx.LevelNames).
	// It also controls how much of a peer address is logged: debug prints it in
	// full, info/warn/error mask the last two IPv4 octets, none logs nothing.
	LogLevel string `yaml:"log_level"`
}

// CarrierConfig describes the fake-TCP link.
type CarrierConfig struct {
	// VPSIP is the server's (filtered) public IP.
	//   - client: REQUIRED — the address to send to and to accept replies from.
	//   - server: OPTIONAL — reply source IP. If empty, it is auto-derived per
	//     client from the destination IP of inbound packets (recommended; also
	//     correct behind 1:1-NAT clouds). Set it only to force a specific source.
	VPSIP string `yaml:"vps_ip"`
	// ServerPort is the carrier TCP port the server "listens" on (vio_tcp_server_port).
	ServerPort uint16 `yaml:"server_port"`
	// ClientPort is the carrier TCP source port the client uses (vio_tcp_client_port);
	// the base of the reconnect rotation range.
	ClientPort uint16 `yaml:"client_port"`
	// ClientPortSpan rotates the client source port across this many ports (from
	// ClientPort) on each reconnect, so a new session doesn't collide with the
	// server's not-yet-expired old one. 1 = disable. The firewall covers the range.
	ClientPortSpan int `yaml:"client_port_span"`
	// ServerPortSpan makes the server accept this many carrier ports (starting at
	// ServerPort) and the client rotate the destination across them on reconnect,
	// to escape a middlebox that blocks one port. MUST match on both ends. 1 = off.
	ServerPortSpan int `yaml:"server_port_span"`
	// Interface is the NIC to capture/inject on. Empty = auto-detect the
	// interface used to reach VPSIP.
	Interface string `yaml:"interface"`
	// MTU is the maximum carrier payload (bytes placed in one TCP segment).
	// The transport layer is told to stay under this to avoid IP fragmentation.
	MTU int `yaml:"mtu"`
	// TCPFlags are the TCP control bits set on every crafted carrier segment:
	// any of ack, psh (push), urg, fin. Default [ack, psh] — what a real
	// mid-stream data segment carries. syn and rst are refused: a SYN is the one
	// packet the GFW checks against its IP blocklist, and a RST tears the flow
	// down on every middlebox in the path. Set per side; the peer does not care
	// which bits arrive.
	TCPFlags []string `yaml:"tcp_flags"`
	// SeqMode is fixed|random|realistic (default fixed) — what the TCP sequence
	// numbers of crafted segments do. See carrier.SeqMode for the detail; in
	// short, fixed and random hold seq still and run at full speed, realistic
	// advances it and is therefore capped (and clamped — see EffectiveKCP) at one
	// unscaled 64 KB window per RTT. MUST MATCH on both ends.
	SeqMode string `yaml:"seq_mode"`
	// SendResetAndWaitBeforeConnect is yes|no (default no): also reset and wait 12s
	// before EVERY connect attempt. Recovery only — for a tuple left poisoned by a
	// run that never released it (older build, crash, kill -9). Normal operation
	// needs nothing, because the client already resets each tuple as it lets go.
	SendResetAndWaitBeforeConnect string `yaml:"send_reset_and_wait_before_connect"`
}

// FirewallConfig controls RST suppression.
type FirewallConfig struct {
	Manage FirewallPolicy `yaml:"manage"`
}

// AuthConfig holds the pre-shared secret used for carrier crypto and the
// per-stream connect handshake.
type AuthConfig struct {
	Key string `yaml:"key"`
}

// KCPConfig mirrors kcp-go's tunables plus the smux flow-control windows.
// See the profiles in config/*.example.yaml and GO.md for per-line-speed values.
type KCPConfig struct {
	NoDelay   int `yaml:"nodelay"`    // 1 = low-latency mode (fast flush/ACK); 0 = normal
	Interval  int `yaml:"interval"`   // internal update period, ms (10 responsive .. 40 low-CPU)
	Resend    int `yaml:"resend"`     // fast-retransmit after N duplicate ACKs (0 = off)
	NC        int `yaml:"nc"`         // 0 = congestion control ON (adaptive); 1 = OFF (aggressive)
	SndWnd    int `yaml:"sndwnd"`     // send window, packets (max in-flight sent)
	RcvWnd    int `yaml:"rcvwnd"`     // receive window, packets. Throughput ~= window*mtu/RTT
	FECData   int `yaml:"fec_data"`   // Reed-Solomon data shards; 0 = FEC off
	FECParity int `yaml:"fec_parity"` // parity shards recovered per group (must match both ends)
	// StreamBuffer / SessionBuffer are the smux flow-control windows in BYTES:
	// per-connection and whole-tunnel. Single-connection throughput is capped at
	// StreamBuffer/RTT. 0 = defaults (4 MB / 16 MB). Raise both for >100 Mbps links.
	StreamBuffer  int `yaml:"stream_buffer"`
	SessionBuffer int `yaml:"session_buffer"`
}

// QUICConfig holds QUIC-specific knobs.
type QUICConfig struct {
	// KeepAlivePeriod in seconds (0 = library default).
	KeepAlivePeriod int `yaml:"keepalive_period"`
	// MaxIdleTimeout in seconds.
	MaxIdleTimeout int `yaml:"max_idle_timeout"`
}

// Forward is a single client-side listener that maps to a server backend port.
type Forward struct {
	Proto      string `yaml:"proto"` // "tcp" or "udp"
	Listen     string `yaml:"listen"`
	TargetPort uint16 `yaml:"target_port"`
}

// ClientConfig is the client half.
type ClientConfig struct {
	// Socks5Listen, if non-empty, exposes a SOCKS5 proxy (server dials arbitrary targets).
	Socks5Listen string `yaml:"socks5_listen"`
	// Forwards are fixed local:remote-port maps (server dials backend_ip:target_port).
	Forwards []Forward `yaml:"forwards"`
	// KeepAliveSeconds is the carrier/session heartbeat period (keeps NAT pinhole open).
	KeepAliveSeconds int `yaml:"keepalive_seconds"`
	// ReconnectSeconds is the delay between reconnection attempts.
	ReconnectSeconds int `yaml:"reconnect_seconds"`
}

// ServerConfig is the server half.
type ServerConfig struct {
	// BackendIP is where forwarded connections are dialed (xray_server_ip_address).
	BackendIP string `yaml:"backend_ip"`
	// AllowSocks5, when true, lets clients request arbitrary targets (SOCKS mode).
	AllowSocks5 bool `yaml:"allow_socks5"`
	// AllowedPorts restricts which destination ports a client may reach (applies
	// to both port-forward and SOCKS targets). Empty = no restriction (any port).
	// e.g. [443, 2096, 2052] lets clients reach only those ports.
	AllowedPorts []int `yaml:"allowed_ports"`
}

// Default returns a Config populated with sensible defaults, matching the
// port numbers used by the reference Python implementation where relevant.
func Default() Config {
	return Config{
		Mode:      ModeClient,
		Transport: TransportKCP,
		Carrier: CarrierConfig{
			ServerPort:                    45000,
			ClientPort:                    40000,
			ClientPortSpan:                8,
			ServerPortSpan:                8,
			MTU:                           1400,
			TCPFlags:                      []string{"ack", "psh"},
			SeqMode:                       string(carrier.SeqFixed),
			SendResetAndWaitBeforeConnect: "no",
		},
		Firewall: FirewallConfig{Manage: FirewallAsk},
		Auth:     AuthConfig{Key: "change-me"},
		KCP: KCPConfig{
			NoDelay:       1,
			Interval:      10,
			Resend:        2,
			NC:            1,   // no congestion control = KCP's normal mode (nc=0/CC underperforms on this carrier)
			SndWnd:        128, // ~BDP for a slow link; bounds bufferbloat. Raise for faster links (see profiles)
			RcvWnd:        128,
			FECData:       0, // FEC off by default (saves ~30% bandwidth); enable on lossy links
			FECParity:     0,
			StreamBuffer:  0, // 0 = auto-size smux buffers from the KCP window
			SessionBuffer: 0,
		},
		QUIC: QUICConfig{KeepAlivePeriod: 4, MaxIdleTimeout: 8},
		Client: ClientConfig{
			KeepAliveSeconds: 4,
			ReconnectSeconds: 2,
		},
		Server:   ServerConfig{BackendIP: "127.0.0.1"},
		LogLevel: "info",
	}
}

// ResetAndWaitBeforeConnect reports whether send_reset_and_wait_before_connect is
// on. Validate has already rejected anything unrecognised.
func (c Config) ResetAndWaitBeforeConnect() bool {
	on, _ := parseYesNo(c.Carrier.SendResetAndWaitBeforeConnect)
	return on
}

// parseYesNo reads a yes/no config value. Empty means no. true/false are accepted
// too, since YAML users reach for them by reflex.
func parseYesNo(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "no", "false", "n":
		return false, nil
	case "yes", "true", "y":
		return true, nil
	}
	return false, fmt.Errorf("want yes or no, got %q", s)
}

// TransportMTU is the payload budget to hand the reliability layer: the
// configured carrier MTU less any TCP options the carrier itself adds per
// segment.
//
// seq_mode: realistic spends 12 bytes on the timestamp option. Without this
// subtraction, turning it on would grow every IP packet by 12 bytes, and a path
// sitting exactly at its MTU would start silently black-holing them (the carrier
// sets DF). Keeping the wire size identical means switching modes cannot break a
// link that was working.
func (c Config) TransportMTU() int {
	mode, err := carrier.ParseSeqMode(c.Carrier.SeqMode)
	if err != nil {
		return c.Carrier.MTU // unvalidated config; Validate reports the real error
	}
	return c.Carrier.MTU - carrier.TCPOptionBytes(mode)
}

// EffectiveKCP returns the KCP settings actually used, and whether the send
// window had to be reduced from the configured value.
//
// seq_mode: realistic advances the carrier's sequence number as it sends, which
// puts it under a middlebox's window ceiling: it drops anything more than one
// unscaled window (65535 bytes, since no SYN means no window scale) past the
// peer's last ack. The default sndwnd of 128 packets is ~180 KB in flight, nearly
// three times that — and overrunning the ceiling does not throttle the link, it
// kills it, because the dropped packets are precisely the ones that would have
// advanced the ack that reopens the window. Clamping the window turns a permanent
// stall into a plain rate cap of roughly 64 KB/RTT.
//
// The other two modes hold seq still, so no ceiling applies and nothing is
// clamped. Each side clamps its own send window, which is the one it controls.
func (c Config) EffectiveKCP() (KCPConfig, bool) {
	k := c.KCP
	mode, err := carrier.ParseSeqMode(c.Carrier.SeqMode)
	if err != nil {
		return k, false // unvalidated config; Validate reports the real error
	}
	limit := carrier.InFlightLimit(mode)
	perPacket := c.TransportMTU()
	if limit <= 0 || perPacket <= 0 {
		return k, false
	}
	maxWnd := limit / perPacket
	if maxWnd < 1 {
		maxWnd = 1
	}
	if k.SndWnd <= maxWnd {
		return k, false
	}
	k.SndWnd = maxWnd
	return k, true
}

// EffectiveAttrs returns the settings that actually took effect, as slog
// key/value pairs, for a single "this is what I am running with" line at
// startup. It covers every knob the Windows GUI has no widget for (interface,
// the kcp/quic tuning, tcp_flags, seq_mode, the keepalive/reconnect timers,
// log_level), which is the only way a GUI user can confirm that a value set in
// their YAML was honoured rather than silently replaced by a default.
//
// auth.key is deliberately absent: this line is meant to be pasteable.
func (c Config) EffectiveAttrs() []any {
	// Report what the carrier will actually do, not the raw strings: an omitted
	// or blank tcp_flags/seq_mode resolves to the default, and printing "" there
	// would be misleading in a line titled "settings in effect". Validate has
	// already rejected anything unparseable, so the errors cannot bite here.
	flags, _ := carrier.ParseTCPFlags(c.Carrier.TCPFlags)
	seqMode, _ := carrier.ParseSeqMode(c.Carrier.SeqMode)
	a := []any{
		"transport", string(c.Transport),
		"interface", c.Carrier.Interface,
		"mtu", c.Carrier.MTU,
		// The payload budget after the carrier's own header options, so a shrunken
		// figure in realistic mode is visible rather than mysterious.
		"transport_mtu", c.TransportMTU(),
		"server_port", c.Carrier.ServerPort,
		"server_port_span", c.Carrier.ServerPortSpan,
		"tcp_flags", flags.String(),
		"seq_mode", string(seqMode),
		"log_level", c.LogLevel,
	}
	if c.Mode == ModeClient {
		a = append(a,
			"client_port", c.Carrier.ClientPort,
			"client_port_span", c.Carrier.ClientPortSpan,
			"reset_and_wait_before_connect", c.ResetAndWaitBeforeConnect(),
			"keepalive_s", c.Client.KeepAliveSeconds,
			"reconnect_s", c.Client.ReconnectSeconds,
		)
	} else {
		a = append(a,
			"backend_ip", c.Server.BackendIP,
			"allow_socks5", c.Server.AllowSocks5,
			"allowed_ports", c.Server.AllowedPorts,
		)
	}
	switch c.Transport {
	case TransportKCP:
		// The effective window, not the configured one: realistic mode clamps it,
		// and a line titled "settings in effect" that printed the unclamped value
		// would send anyone debugging throughput off in the wrong direction.
		kcp, clamped := c.EffectiveKCP()
		sndwnd := any(kcp.SndWnd)
		if clamped {
			sndwnd = fmt.Sprintf("%d (clamped from %d by seq_mode: realistic)", kcp.SndWnd, c.KCP.SndWnd)
		}
		a = append(a,
			"kcp_nodelay", kcp.NoDelay,
			"kcp_interval", kcp.Interval,
			"kcp_resend", kcp.Resend,
			"kcp_nc", kcp.NC,
			"kcp_sndwnd", sndwnd,
			"kcp_rcvwnd", kcp.RcvWnd,
			"kcp_fec", fmt.Sprintf("%d/%d", kcp.FECData, kcp.FECParity),
			"kcp_stream_buffer", kcp.StreamBuffer,
			"kcp_session_buffer", kcp.SessionBuffer,
		)
	case TransportQUIC:
		a = append(a,
			"quic_keepalive_period", c.QUIC.KeepAlivePeriod,
			"quic_max_idle_timeout", c.QUIC.MaxIdleTimeout,
		)
	}
	return a
}

// Load reads a YAML file over the defaults and validates it.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate checks required fields for the selected mode.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeClient, ModeServer:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeClient, ModeServer, c.Mode)
	}
	switch c.Transport {
	case TransportKCP, TransportQUIC:
	default:
		return fmt.Errorf("transport must be %q or %q, got %q", TransportKCP, TransportQUIC, c.Transport)
	}
	switch c.Firewall.Manage {
	case FirewallAsk, FirewallYes, FirewallNo:
	default:
		return fmt.Errorf("firewall.manage must be ask|yes|no, got %q", c.Firewall.Manage)
	}
	if c.Mode == ModeClient && c.Carrier.VPSIP == "" {
		return fmt.Errorf("carrier.vps_ip is required for client mode")
	}
	if c.Carrier.ServerPort == 0 {
		return fmt.Errorf("carrier.server_port is required")
	}
	// client_port is the client's carrier source port; the server ignores it
	// (it learns each client's real, NAT-translated port from sniffed packets).
	if c.Mode == ModeClient && c.Carrier.ClientPort == 0 {
		return fmt.Errorf("carrier.client_port is required for client mode")
	}
	if c.Carrier.ClientPortSpan < 0 || int(c.Carrier.ClientPort)+c.Carrier.ClientPortSpan-1 > 65535 {
		return fmt.Errorf("carrier.client_port_span invalid: client_port + span - 1 exceeds 65535")
	}
	if c.Carrier.ServerPortSpan < 0 || int(c.Carrier.ServerPort)+c.Carrier.ServerPortSpan-1 > 65535 {
		return fmt.Errorf("carrier.server_port_span invalid: server_port + span - 1 exceeds 65535")
	}
	if c.Carrier.MTU < 576 || c.Carrier.MTU > 1500 {
		return fmt.Errorf("carrier.mtu must be between 576 and 1500, got %d", c.Carrier.MTU)
	}
	// The carrier package owns the vocabulary for these two, so it validates them.
	if _, err := carrier.ParseTCPFlags(c.Carrier.TCPFlags); err != nil {
		return fmt.Errorf("carrier.tcp_flags: %w", err)
	}
	if _, err := carrier.ParseSeqMode(c.Carrier.SeqMode); err != nil {
		return fmt.Errorf("carrier.seq_mode: %w", err)
	}
	if _, err := logx.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("log_level: %w", err)
	}
	if _, err := parseYesNo(c.Carrier.SendResetAndWaitBeforeConnect); err != nil {
		return fmt.Errorf("carrier.send_reset_and_wait_before_connect: %w", err)
	}
	if strings.TrimSpace(c.Auth.Key) == "" {
		return fmt.Errorf("auth.key is required")
	}
	if c.Mode == ModeClient {
		if c.Client.Socks5Listen == "" && len(c.Client.Forwards) == 0 {
			return fmt.Errorf("client needs at least a socks5_listen or one forward")
		}
		for i, f := range c.Client.Forwards {
			if f.Proto != "tcp" && f.Proto != "udp" {
				return fmt.Errorf("client.forwards[%d].proto must be tcp|udp", i)
			}
			if f.Listen == "" || f.TargetPort == 0 {
				return fmt.Errorf("client.forwards[%d] needs listen and target_port", i)
			}
		}
	}
	if c.Mode == ModeServer {
		for i, p := range c.Server.AllowedPorts {
			if p < 1 || p > 65535 {
				return fmt.Errorf("server.allowed_ports[%d]=%d is out of range 1-65535", i, p)
			}
		}
	}
	return nil
}
