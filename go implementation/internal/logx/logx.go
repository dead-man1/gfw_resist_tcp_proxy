// Package logx owns two things the whole program shares: parsing the
// `log_level` config value into an slog.Level, and the privacy rules for peer
// addresses in log output.
//
// A gfk server log is the one place a client's real IP appears, so the level
// also decides how much of that address is printed:
//
//	debug          full address     198.51.100.7:40000
//	info/warn/error masked          198.51.*.*:40000
//	none           nothing is logged at all
//
// The masking is deliberately coarse (the last two IPv4 octets go) so a log can
// be pasted into an issue without identifying the user behind it, while still
// showing the network/country the connection came from.
package logx

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
)

// LevelNone sits above every real level, so a handler configured with it emits
// nothing. It is the level for `log_level: none`.
const LevelNone = slog.LevelError + 4

// LevelNames lists the accepted log_level values, for config errors and docs.
const LevelNames = "none|error|warn|info|debug"

// ParseLevel maps a config log_level string to an slog.Level. An empty value
// means info.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none", "off", "silent", "quiet":
		return LevelNone, nil
	case "error", "err":
		return slog.LevelError, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "debug", "verbose":
		return slog.LevelDebug, nil
	}
	return slog.LevelInfo, fmt.Errorf("unknown value %q, want one of %s", s, LevelNames)
}

// redaction is how much of a peer address may be logged.
type redaction int32

const (
	redactMask redaction = iota // default: keep the first two IPv4 octets
	redactFull                  // debug: print the address verbatim
	redactHide                  // none: omit the address entirely
)

// mode is process-wide: the log level is a single startup decision, and the
// alternative (threading a redaction setting through every logger) would touch
// every call site for no gain. Atomic so the GUI can change it between runs.
var mode atomic.Int32

// SetLevel installs the redaction policy implied by the active log level. Call
// it once, next to the logger construction.
func SetLevel(l slog.Level) {
	switch {
	case l >= LevelNone:
		mode.Store(int32(redactHide))
	case l <= slog.LevelDebug:
		mode.Store(int32(redactFull))
	default:
		mode.Store(int32(redactMask))
	}
}

// Peer returns a "peer" log attribute for a carrier peer address, redacted for
// the active log level. When addresses are hidden it returns the zero Attr,
// which slog handlers elide — so the message still appears, without the IP.
func Peer(addr any) slog.Attr { return Addr("peer", addr) }

// Addr is Peer with a caller-chosen key, for the other places an address is
// logged (a client's own view of the server, a resolved target).
func Addr(key string, addr any) slog.Attr {
	var s string
	switch v := addr.(type) {
	case nil:
		return slog.Attr{}
	case string:
		s = v
	case net.Addr:
		if v == nil {
			return slog.Attr{}
		}
		s = v.String()
	case net.IP:
		s = v.String()
	default:
		s = fmt.Sprint(v)
	}

	switch redaction(mode.Load()) {
	case redactHide:
		return slog.Attr{}
	case redactFull:
		return slog.String(key, s)
	default:
		return slog.String(key, MaskAddr(s))
	}
}

// MaskAddr masks the host part of an "ip:port" (or bare host) string, keeping
// the port. IPv4 keeps its first two octets ("203.0.*.*:443"), IPv6 its first
// two groups, and a name that is not an IP is dropped entirely — a hostname can
// identify a user as precisely as an address.
func MaskAddr(s string) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return maskHost(s) // no port: the whole string is the host
	}
	masked := maskHost(host)
	if strings.Contains(masked, ":") { // IPv6 literals need brackets before the port
		return "[" + masked + "]:" + port
	}
	return masked + ":" + port
}

func maskHost(host string) string {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "*"
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.*.*", v4[0], v4[1])
	}
	v6 := ip.To16()
	return fmt.Sprintf("%x:%x:*", binary.BigEndian.Uint16(v6[0:2]), binary.BigEndian.Uint16(v6[2:4]))
}
