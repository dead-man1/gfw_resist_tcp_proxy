// Package carrier implements the "TCP violation" transport: a connectionless
// bidirectional datagram pipe built by crafting and sniffing TCP ACK+PSH
// packets that carry arbitrary payloads, with no SYN handshake. It is exposed
// as a net.PacketConn so reliability layers (KCP, QUIC) can run on top of it.
//
// The GFW enforces its IP blocklist only on TCP SYN packets; by never sending
// a SYN and only emitting mid-stream-looking ACK+PSH segments, traffic to and
// from a blocked VPS IP passes uninspected.
package carrier

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Addr is a carrier peer address (the other end of the fake-TCP link).
// It implements net.Addr so KCP/QUIC can key sessions on it.
type Addr struct {
	IP   net.IP
	Port uint16
}

// Network returns the pseudo-network name.
func (a *Addr) Network() string { return "gfk" }

// String returns "ip:port".
func (a *Addr) String() string {
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
}

// addrFromNet coerces any net.Addr (our *Addr, or a *net.UDPAddr handed to us
// by kcp-go's string-resolving constructors) into IP+port.
func addrFromNet(a net.Addr) (net.IP, uint16, bool) {
	switch v := a.(type) {
	case *Addr:
		return v.IP, v.Port, true
	case *net.UDPAddr:
		return v.IP, uint16(v.Port), true
	case *net.TCPAddr:
		return v.IP, uint16(v.Port), true
	default:
		if host, port, err := net.SplitHostPort(a.String()); err == nil {
			ip := net.ParseIP(host)
			p, perr := strconv.Atoi(port)
			if ip != nil && perr == nil {
				return ip, uint16(p), true
			}
		}
	}
	return nil, 0, false
}

// Our receiver matches carrier packets by port and reads the payload; it never
// inspects TCP seq/ack. In the default "fixed" seq mode we therefore keep seq
// and ack CONSTANT and low, so that stateful conntrack/NAT on the path (home
// router, ISP) always sees in-window packets. A climbing seq with a frozen ack
// would eventually exceed the peer's ~64 KB window (the ack cannot advance,
// since there is no real handshake), and the middlebox would start dropping
// that direction — observed in the field as the return path dying at ~24s.
// seq_mode: realistic avoids that trap differently: seq advances by payload
// length AND the ack mirrors what the peer sent, so the pair stays consistent
// the way a real stream's does. See seqState in carrier.go.
const (
	carrierSeq = 1
	carrierAck = 1
)

// TCPFlags selects which TCP control bits crafted carrier segments carry
// (config carrier.tcp_flags).
type TCPFlags struct {
	ACK bool
	PSH bool
	URG bool
	FIN bool
}

// DefaultTCPFlags is what a mid-stream data segment normally carries, and what
// the carrier used before the flags became configurable.
func DefaultTCPFlags() TCPFlags { return TCPFlags{ACK: true, PSH: true} }

// ParseTCPFlags turns config names into a TCPFlags. An empty list means the
// default (ACK+PSH).
//
// SYN and RST are rejected, not merely discouraged: a SYN is the one packet the
// GFW inspects against its IP blocklist, so sending one defeats the entire
// point of the carrier; a RST tells every stateful middlebox on the path (and
// the peer's kernel) to tear the flow down.
func ParseTCPFlags(names []string) (TCPFlags, error) {
	if len(names) == 0 {
		return DefaultTCPFlags(), nil
	}
	var f TCPFlags
	for _, raw := range names {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "ack":
			f.ACK = true
		case "psh", "push":
			f.PSH = true
		case "urg", "urgent":
			f.URG = true
		case "fin":
			f.FIN = true
		case "syn":
			return f, fmt.Errorf("syn cannot be set: a SYN is what the GFW matches against its IP blocklist")
		case "rst", "reset":
			return f, fmt.Errorf("rst cannot be set: it would tear the carrier flow down")
		case "":
			continue
		default:
			return f, fmt.Errorf("unknown flag %q, want any of ack|psh|urg|fin", raw)
		}
	}
	if f == (TCPFlags{}) {
		return f, fmt.Errorf("no flags selected, want at least one of ack|psh|urg|fin")
	}
	return f, nil
}

// String renders the set bits in the config's own vocabulary, for startup logs.
func (f TCPFlags) String() string {
	var set []string
	for _, b := range []struct {
		on   bool
		name string
	}{{f.ACK, "ack"}, {f.PSH, "psh"}, {f.URG, "urg"}, {f.FIN, "fin"}} {
		if b.on {
			set = append(set, b.name)
		}
	}
	if len(set) == 0 {
		return "none"
	}
	return strings.Join(set, "+")
}

// SeqMode selects how the TCP sequence/ack numbers of crafted segments evolve.
type SeqMode string

const (
	// SeqFixed pins seq and ack to 1 on every segment (the original behaviour):
	// maximally safe for window-tracking middleboxes, but a give-away to any
	// observer that looks at more than one packet.
	SeqFixed SeqMode = "fixed"
	// SeqRealistic starts from a random ISN and advances seq by the payload
	// length, acking what the peer sent, like a real established connection.
	SeqRealistic SeqMode = "realistic"
)

// ParseSeqMode validates a config seq_mode value; empty means fixed.
func ParseSeqMode(s string) (SeqMode, error) {
	switch SeqMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", SeqFixed:
		return SeqFixed, nil
	case SeqRealistic:
		return SeqRealistic, nil
	}
	return SeqFixed, fmt.Errorf("unknown value %q, want %q or %q", s, SeqFixed, SeqRealistic)
}

// craftSegment serializes a full IPv4 packet carrying a TCP segment with the
// given flags, sequence numbers and payload. It returns the raw IP bytes (no
// Ethernet header).
func craftSegment(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags TCPFlags, payload []byte) ([]byte, error) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		ACK:     flags.ACK,
		// PSH means "deliver what you have now", which is meaningless on an empty
		// segment; a real stack never sets it there, so neither do we.
		PSH:    flags.PSH && len(payload) > 0,
		URG:    flags.URG && len(payload) > 0,
		FIN:    flags.FIN,
		Window: 65535,
	}
	if tcp.URG {
		// A set URG bit with a zero urgent pointer is a well-known invalid
		// combination that middleboxes normalise or drop; point it past the last
		// payload byte, as a sender flagging the whole segment would.
		tcp.Urgent = uint16(len(payload))
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// segment is a parsed inbound carrier packet.
type segment struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	synOnly bool   // true if SYN set (we ignore these — they are not carrier data)
	seq     uint32 // the peer's sequence number, mirrored back as our ack in realistic mode
	payload []byte
}

// parseIPv4 parses raw IPv4 bytes into a TCP segment. ok is false if the packet
// is not IPv4+TCP or has no payload we care about.
func parseIPv4(data []byte) (segment, bool) {
	var seg segment
	pkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipl := pkt.Layer(layers.LayerTypeIPv4)
	if ipl == nil {
		return seg, false
	}
	ip, _ := ipl.(*layers.IPv4)
	tcl := pkt.Layer(layers.LayerTypeTCP)
	if tcl == nil {
		return seg, false
	}
	tcp, _ := tcl.(*layers.TCP)
	seg.srcIP = ip.SrcIP
	seg.dstIP = ip.DstIP
	seg.srcPort = uint16(tcp.SrcPort)
	seg.dstPort = uint16(tcp.DstPort)
	seg.synOnly = tcp.SYN
	seg.seq = tcp.Seq
	seg.payload = tcp.Payload
	return seg, true
}

// localIPToward returns the source IP the OS would use to reach dst. The UDP
// "dial" only connect()s (a route lookup) and sends nothing, so it is cheap and
// side-effect-free. The destination port is arbitrary — 53 by convention, since
// no packet is ever emitted to it; the kernel picks the local source port.
func localIPToward(dst net.IP) (net.IP, error) {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP, nil
}
