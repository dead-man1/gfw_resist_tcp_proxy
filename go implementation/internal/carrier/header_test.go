package carrier

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// tcpHeader pulls the fields we craft back out of a raw IPv4 packet, so the
// assertions below read the wire, not our own structs.
type tcpHeader struct {
	seq, ack   uint32
	flags      byte
	urgent     uint16
	payloadLen int
}

func parseHeader(t *testing.T, ipPkt []byte) tcpHeader {
	t.Helper()
	ihl := int(ipPkt[0]&0x0f) * 4
	tcp := ipPkt[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	return tcpHeader{
		seq:        binary.BigEndian.Uint32(tcp[4:8]),
		ack:        binary.BigEndian.Uint32(tcp[8:12]),
		flags:      tcp[13],
		urgent:     binary.BigEndian.Uint16(tcp[18:20]),
		payloadLen: len(tcp) - dataOff,
	}
}

const (
	flagFIN = 1 << 0
	flagSYN = 1 << 1
	flagRST = 1 << 2
	flagPSH = 1 << 3
	flagACK = 1 << 4
	flagURG = 1 << 5
)

func TestParseTCPFlags(t *testing.T) {
	if got, err := ParseTCPFlags(nil); err != nil || got != DefaultTCPFlags() {
		t.Errorf("empty list should give the ack+psh default, got %v (%v)", got, err)
	}
	got, err := ParseTCPFlags([]string{"ACK", " push ", "urg", "fin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := (TCPFlags{ACK: true, PSH: true, URG: true, FIN: true}); got != want {
		t.Errorf("flags = %v, want %v", got, want)
	}
	if got.String() != "ack+psh+urg+fin" {
		t.Errorf("String() = %q", got.String())
	}

	// syn and rst are the two the carrier cannot survive.
	for _, bad := range [][]string{{"ack", "syn"}, {"ack", "rst"}, {"ack", "reset"}, {"ack", "cwr"}, {}} {
		if len(bad) == 0 {
			continue
		}
		if _, err := ParseTCPFlags(bad); err == nil {
			t.Errorf("ParseTCPFlags(%v) should have failed", bad)
		}
	}
	// An explicit list that selects nothing is a config mistake, not "no flags".
	if _, err := ParseTCPFlags([]string{"", "  "}); err == nil {
		t.Error("a list with no usable flag should fail")
	}
}

// TestCraftSegmentFlags checks the requested bits land on the wire, and that the
// payload-dependent ones behave like a real stack's.
func TestCraftSegmentFlags(t *testing.T) {
	src, dst := net.IPv4(192, 168, 1, 5), net.IPv4(203, 0, 113, 10)

	pkt, err := testSegment(src, dst, 40000, 45000, 1, 1, TCPFlags{ACK: true, PSH: true, URG: true, FIN: true}, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	h := parseHeader(t, pkt)
	for _, c := range []struct {
		bit  byte
		name string
	}{{flagACK, "ACK"}, {flagPSH, "PSH"}, {flagURG, "URG"}, {flagFIN, "FIN"}} {
		if h.flags&c.bit == 0 {
			t.Errorf("%s should be set, flags = %08b", c.name, h.flags)
		}
	}
	if h.flags&(flagSYN|flagRST) != 0 {
		t.Errorf("SYN/RST must never be set, flags = %08b", h.flags)
	}
	if h.urgent != 5 {
		t.Errorf("urgent pointer = %d, want the payload length 5 (a zero pointer with URG is invalid)", h.urgent)
	}

	// PSH/URG mean nothing on an empty segment, so they must be dropped there.
	pkt, err = testSegment(src, dst, 40000, 45000, 1, 1, TCPFlags{ACK: true, PSH: true, URG: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h = parseHeader(t, pkt)
	if h.flags&flagACK == 0 {
		t.Error("ACK should still be set on an empty segment")
	}
	if h.flags&(flagPSH|flagURG) != 0 {
		t.Errorf("PSH/URG must not be set without payload, flags = %08b", h.flags)
	}
}

func TestParseSeqMode(t *testing.T) {
	for _, in := range []string{"", "fixed", "FIXED", " fixed "} {
		if got, err := ParseSeqMode(in); err != nil || got != SeqFixed {
			t.Errorf("ParseSeqMode(%q) = %v, %v; want fixed", in, got, err)
		}
	}
	if got, err := ParseSeqMode("realistic"); err != nil || got != SeqRealistic {
		t.Errorf("ParseSeqMode(realistic) = %v, %v", got, err)
	}
	if _, err := ParseSeqMode("random"); err == nil {
		t.Error("ParseSeqMode should reject an unknown mode")
	}
}

// newTestClient builds a client Carrier over a fake backend, in the given seq
// mode.
func newTestClient(f *fakeIO, mode SeqMode) *Carrier {
	c := &Carrier{
		opts: Options{
			Role: RoleClient, VPSIP: net.IPv4(203, 0, 113, 10),
			ServerPort: 45000, ServerPortSpan: 4,
			ClientPort: 40000, ClientPortSpan: 2,
		},
		localIP:  net.IPv4(192, 168, 1, 5),
		pio:      f,
		tcpFlags: DefaultTCPFlags(),
		seqMode:  mode,
		rx:       make(chan rxPacket, 16),
		closed:   make(chan struct{}),
	}
	c.curClientPort.Store(uint32(c.opts.ClientPort))
	c.curServerPort.Store(uint32(c.opts.ServerPort))
	c.peer = &Addr{IP: c.opts.VPSIP, Port: c.opts.ServerPort}
	if mode == SeqRealistic {
		c.clientSeq = newSeqState()
	}
	go c.recvLoop()
	return c
}

// TestRealisticSeqAdvancesAndAcks: seq must advance by exactly the bytes sent,
// and the ack must follow what the peer sent — the two properties that make the
// numbers survive a window-tracking middlebox.
func TestRealisticSeqAdvancesAndAcks(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	send := func(payload string) tcpHeader {
		if _, err := c.WriteTo([]byte(payload), c.peer); err != nil {
			t.Fatal(err)
		}
		return parseHeader(t, <-f.sent)
	}

	h1 := send("aaaa")
	h2 := send("bbbbbbbbbbbbbbbb")
	if h2.seq != h1.seq+4 {
		t.Errorf("seq advanced by %d, want the 4 bytes sent", h2.seq-h1.seq)
	}
	h3 := send("c")
	if h3.seq != h2.seq+16 {
		t.Errorf("seq advanced by %d, want the 16 bytes sent", h3.seq-h2.seq)
	}
	if h1.seq == carrierSeq {
		t.Error("realistic mode should not start at the fixed seq of 1")
	}
	// Neither number may be the tell-tale 1 before the peer has spoken: at that
	// point the ack is a plausible guess, not a placeholder.
	if h1.ack == carrierAck {
		t.Error("ack before any inbound packet should be a random plausible value, not 1")
	}
	if h1.ack != h2.ack || h2.ack != h3.ack {
		t.Errorf("the guessed ack should be stable until the peer speaks: %d, %d, %d", h1.ack, h2.ack, h3.ack)
	}

	// Feed an inbound segment: the next ack must cover its last byte.
	pkt, err := testSegment(c.opts.VPSIP, c.localIP, 45000, 40000, 900000, 1, DefaultTCPFlags(), []byte("1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	f.inbound <- pkt
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if h := send("d"); h.ack != 900000+10 {
		t.Errorf("ack = %d, want peer seq 900000 + 10 payload bytes", h.ack)
	}

	// A port rotation is a new flow, so it must start a new ISN.
	before := send("e").seq
	c.RotateClientPort()
	if after := send("f").seq; after == before+1 {
		t.Error("port rotation should restart the sequence with a fresh ISN")
	}
}

// TestAckIsRealisticFromTheFirstPacket: in realistic mode the ack must never be
// the placeholder 1, must adopt the peer's real position as soon as one packet
// arrives (whichever side of the guess it falls on), and must then only advance —
// a real cumulative ack never regresses.
func TestAckIsRealisticFromTheFirstPacket(t *testing.T) {
	// The guess must be replaced even when it sits "after" the peer's real
	// position, or the ack would freeze and the flow would look stuck. Both
	// directions of that comparison are exercised here.
	for _, peerSeq := range []uint32{5, 1 << 30, 0xFFFFFF00} {
		s := newSeqState()
		guess := s.ack
		if guess == carrierAck {
			t.Fatal("a fresh flow should not ack 1")
		}
		s.observe(peerSeq, 10, 0, false)
		if _, ack, _ := s.next(1); ack != peerSeq+10 {
			t.Errorf("peer_seq=%d: ack = %d, want %d (guess was %d)", peerSeq, ack, peerSeq+10, guess)
		}
	}

	// Forward motion only: a reordered/retransmitted earlier segment must not
	// pull the ack back.
	s := newSeqState()
	s.observe(100000, 100, 0, false) // ack -> 100100
	s.observe(90000, 100, 0, false)  // an older segment arriving late
	if _, ack, _ := s.next(1); ack != 100100 {
		t.Errorf("ack = %d, want it to stay at 100100; a cumulative ack never regresses", ack)
	}
	s.observe(100100, 400, 0, false) // genuinely new data
	if _, ack, _ := s.next(1); ack != 100500 {
		t.Errorf("ack = %d, want 100500", ack)
	}

	// Serial arithmetic: when the peer's own counter restarts (its overflow), the
	// large backward step reads as forward motion and must be adopted, not ignored.
	s = newSeqState()
	s.observe(0xFFFFFF00, 16, 0, false) // ack -> 0xFFFFFF10
	s.observe(0x20000000, 8, 0, false)  // peer restarted at a fresh ISN
	if _, ack, _ := s.next(1); ack != 0x20000008 {
		t.Errorf("ack = %#x, want %#x after the peer restarted", ack, 0x20000008)
	}

	// A fixed-mode flow is unaffected: still the constant pair.
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()
	if _, err := c.WriteTo([]byte("x"), c.peer); err != nil {
		t.Fatal(err)
	}
	if h := parseHeader(t, <-f.sent); h.seq != carrierSeq || h.ack != carrierAck {
		t.Errorf("fixed mode: seq/ack = %d/%d, want 1/1", h.seq, h.ack)
	}
}

// TestSeqOverflowRestartsAtISN: rather than wrapping past 2^32 (which nothing
// re-synchronises, since the peer ignores seq), the flow restarts at its ISN.
func TestSeqOverflowRestartsAtISN(t *testing.T) {
	s := &seqState{isn: 1000, seq: 1000, ack: 1}
	s.seq = 0xFFFFFFF0 // 16 bytes of space left before the wrap

	if seq, _, _ := s.next(10); seq != 0xFFFFFFF0 {
		t.Fatalf("seq = %#x, want the pre-wrap value", seq)
	}
	// 0xFFFFFFFA + 10 would wrap: expect a restart at the ISN instead.
	seq, _, _ := s.next(10)
	if seq != 1000 {
		t.Errorf("seq = %#x, want a restart at the ISN (1000)", seq)
	}
	if next, _, _ := s.next(1); next != 1010 {
		t.Errorf("seq = %d, want the restarted counter to keep climbing (1010)", next)
	}
}

// TestFixedSeqMode: the default mode still pins both numbers to 1 (the
// behaviour that keeps window-tracking NAT happy).
func TestFixedSeqMode(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()

	for _, payload := range []string{"aaaa", "bbbbbbbbbbbbbbbb"} {
		if _, err := c.WriteTo([]byte(payload), c.peer); err != nil {
			t.Fatal(err)
		}
		h := parseHeader(t, <-f.sent)
		if h.seq != carrierSeq || h.ack != carrierAck {
			t.Errorf("fixed mode: seq/ack = %d/%d, want %d/%d", h.seq, h.ack, carrierSeq, carrierAck)
		}
	}
}

// TestServerPerClientSeqState: two clients must not share a sequence counter,
// or each would see the other's bytes reflected in its numbers.
func TestServerPerClientSeqState(t *testing.T) {
	f := newFakeIO()
	c := &Carrier{
		opts:     Options{Role: RoleServer, ServerPort: 45000, ServerPortSpan: 1},
		pio:      f,
		tcpFlags: DefaultTCPFlags(),
		seqMode:  SeqRealistic,
		rx:       make(chan rxPacket, 16),
		closed:   make(chan struct{}),
	}
	c.curServerPort.Store(uint32(c.opts.ServerPort))
	go c.recvLoop()
	defer c.Close()

	addressed := net.IPv4(203, 0, 113, 9)
	a := feedInbound(t, c, f, net.IPv4(198, 51, 100, 7), addressed, "a")
	b := feedInbound(t, c, f, net.IPv4(198, 51, 100, 8), addressed, "b")

	seqOf := func(addr net.Addr, payload string) uint32 {
		if _, err := c.WriteTo([]byte(payload), addr); err != nil {
			t.Fatal(err)
		}
		return parseHeader(t, <-f.sent).seq
	}
	a1 := seqOf(a, "xxxx")
	b1 := seqOf(b, "yyyyyyyy")
	a2 := seqOf(a, "z")
	if a2 != a1+4 {
		t.Errorf("client A seq advanced by %d, want only its own 4 bytes", a2-a1)
	}
	if b2 := seqOf(b, "z"); b2 != b1+8 {
		t.Errorf("client B seq advanced by %d, want only its own 8 bytes", b2-b1)
	}
}
