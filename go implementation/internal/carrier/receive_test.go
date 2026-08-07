package carrier

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// craftRaw builds a carrier-shaped packet with arbitrary TCP flags and sequence
// numbers — including the combinations craftSegment refuses to emit (SYN, RST) —
// so the tests below can probe what the receiver actually accepts.
func craftRaw(t *testing.T, tcp *layers.TCP, payload string) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(198, 51, 100, 7).To4(),
		DstIP:    net.IPv4(203, 0, 113, 9).To4(),
	}
	tcp.SrcPort, tcp.DstPort = 40000, 45000
	tcp.Window = 65535
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload([]byte(payload))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// accepts reports whether the receive loop passed a packet up to the transport.
func accepts(t *testing.T, tcp *layers.TCP, payload string) bool {
	t.Helper()
	f := newFakeIO()
	c := newTestServer(nil, f)
	defer c.Close()

	f.inbound <- craftRaw(t, tcp, payload)
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	_, _, err := c.ReadFrom(buf)
	return err == nil
}

// TestReceiverIgnoresTCPFlags documents the receive contract behind
// "tcp_flags is independent per side": the receiver does NOT require ACK+PSH, or
// any other combination. It rejects exactly two things — a SYN (which would be
// the handshake the GFW inspects) and an empty payload (no carrier data).
//
// Note the RST row: an inbound RST carrying a payload IS accepted. Real kernel
// RSTs carry no payload, so the empty-payload rule already drops them; this only
// documents that the check is payload-based, not flag-based.
func TestReceiverIgnoresTCPFlags(t *testing.T) {
	cases := []struct {
		name string
		tcp  *layers.TCP
		want bool
	}{
		{"ack+psh (what we send by default)", &layers.TCP{ACK: true, PSH: true}, true},
		{"ack only", &layers.TCP{ACK: true}, true},
		{"psh only, no ack", &layers.TCP{PSH: true}, true},
		{"fin+ack", &layers.TCP{FIN: true, ACK: true}, true},
		{"urg+ack", &layers.TCP{URG: true, ACK: true, Urgent: 4}, true},
		{"no flags at all", &layers.TCP{}, true},
		{"rst+ack with payload", &layers.TCP{RST: true, ACK: true}, true},
		{"syn+ack — rejected", &layers.TCP{SYN: true, ACK: true}, false},
		{"syn alone — rejected", &layers.TCP{SYN: true}, false},
	}
	for _, tc := range cases {
		if got := accepts(t, tc.tcp, "data"); got != tc.want {
			t.Errorf("%s: accepted=%v, want %v", tc.name, got, tc.want)
		}
	}

	// An empty payload is dropped whatever the flags say.
	if accepts(t, &layers.TCP{ACK: true, PSH: true}, "") {
		t.Error("an empty-payload segment should be dropped (it carries no tunnel data)")
	}
}

// TestReceiverIgnoresSeqAndAck documents the contract behind "seq_mode is
// independent per side": the receiver never inspects seq or ack, and in
// particular does not expect seq == 1. Any value is carrier data.
func TestReceiverIgnoresSeqAndAck(t *testing.T) {
	for _, n := range []uint32{0, 1, 2, 1000, 1 << 31, 0xFFFFFFFF, 0x7A6B5C4D} {
		tcp := &layers.TCP{ACK: true, PSH: true, Seq: n, Ack: n ^ 0x5A5A5A5A}
		if !accepts(t, tcp, "data") {
			t.Errorf("seq=%d ack=%d was rejected; the receiver must not check sequence numbers",
				n, n^0x5A5A5A5A)
		}
	}
}

// TestReceiverStillMatchesPorts guards the flip side: dropping the flag and seq
// checks must not mean the receiver takes anything off the wire. The port match
// is the whole filter, so it has to hold.
func TestReceiverStillMatchesPorts(t *testing.T) {
	f := newFakeIO()
	c := newTestServer(nil, f) // ServerPort 45000, span defaults to <1 => just 45000
	defer c.Close()

	tcp := &layers.TCP{ACK: true, PSH: true}
	pkt := craftRaw(t, tcp, "data")
	// Rewrite the destination port to one outside the span; everything else stays
	// a perfectly well-formed carrier packet.
	ihl := int(pkt[0]&0x0f) * 4
	pkt[ihl+2], pkt[ihl+3] = 0xC0, 0x00 // dst port 49152
	f.inbound <- pkt

	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, _, err := c.ReadFrom(buf); err == nil {
		t.Error("a packet to a port outside the span must be ignored")
	}
}

// TestReceiverAcceptsAnyFlagsFromRealSender is the round-trip version: whatever
// tcp_flags the peer is configured with, we accept its packets. This is what lets
// the two ends run different tcp_flags settings.
func TestReceiverAcceptsAnyFlagsFromRealSender(t *testing.T) {
	for _, names := range [][]string{{"ack"}, {"ack", "psh"}, {"ack", "psh", "urg"}, {"ack", "fin"}, {"fin"}} {
		flags, err := ParseTCPFlags(names)
		if err != nil {
			t.Fatalf("%v: %v", names, err)
		}
		f := newFakeIO()
		c := newTestServer(nil, f)

		// Craft exactly as a peer configured with these flags would.
		pkt, err := craftSegment(net.IPv4(198, 51, 100, 7), net.IPv4(203, 0, 113, 9),
			40000, 45000, 987654321, 123456789, flags, []byte("data"))
		if err != nil {
			t.Fatal(err)
		}
		f.inbound <- pkt

		buf := make([]byte, 2048)
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		_, _, err = c.ReadFrom(buf)
		c.Close()
		if err != nil {
			t.Errorf("peer sending %s was rejected: %v", fmt.Sprint(names), err)
		}
	}
}
