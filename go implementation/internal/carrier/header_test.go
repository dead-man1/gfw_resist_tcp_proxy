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
	for in, want := range map[string]SeqMode{
		"realistic": SeqRealistic, "REALISTIC": SeqRealistic,
		"random": SeqRandom, " Random ": SeqRandom,
	} {
		if got, err := ParseSeqMode(in); err != nil || got != want {
			t.Errorf("ParseSeqMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSeqMode("plausible"); err == nil {
		t.Error("ParseSeqMode should reject an unknown mode")
	}

	// The two predicates the rest of the carrier branches on. Advances is what
	// subjects a mode to the middlebox window ceiling; Camouflaged is what gives
	// it a seqState at all — and both must say "no" for the zero value, which is
	// the empty string rather than SeqFixed.
	for mode, want := range map[SeqMode][2]bool{
		SeqFixed:     {false, false},
		SeqRandom:    {false, true},
		SeqRealistic: {true, true},
		SeqMode(""):  {false, false},
	} {
		if got := [2]bool{mode.Advances(), mode.Camouflaged()}; got != want {
			t.Errorf("%q: {Advances, Camouflaged} = %v, want %v", mode, got, want)
		}
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
		rxDone:   make(chan struct{}),
	}
	c.curClientPort.Store(uint32(c.opts.ClientPort))
	c.curServerPort.Store(uint32(c.opts.ServerPort))
	c.peer.Store(&Addr{IP: c.opts.VPSIP, Port: c.opts.ServerPort})
	if mode.Camouflaged() {
		c.clientSeq = newSeqState(mode)
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
		if _, err := c.WriteTo([]byte(payload), c.RemoteAddr()); err != nil {
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
		s := newSeqState(SeqRealistic)
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
	s := newSeqState(SeqRealistic)
	s.observe(100000, 100, 0, false) // ack -> 100100
	s.observe(90000, 100, 0, false)  // an older segment arriving late
	if _, ack, _ := s.next(1); ack != 100100 {
		t.Errorf("ack = %d, want it to stay at 100100; a cumulative ack never regresses", ack)
	}
	s.observe(100100, 400, 0, false) // genuinely new data
	if _, ack, _ := s.next(1); ack != 100500 {
		t.Errorf("ack = %d, want 100500", ack)
	}

	// The ack must follow the peer across ITS 2^32 rollover. This is the mirror of
	// TestSeqWrapsLikeRealTCP and just as load-bearing: if the forward-only rule
	// rejected the wrapped value, our ack would freeze at ~2^32 — which is exactly
	// the frozen-ack condition that gets a flow window-dropped, arriving silently
	// after 4.29 GB.
	s = newSeqState(SeqRealistic)
	s.observe(0xFFFFFFE0, 16, 0, false) // ack -> 0xFFFFFFF0
	s.observe(0xFFFFFFF0, 32, 0, false) // peer's stream rolls over: ack -> 0x00000010
	if _, ack, _ := s.next(1); ack != 0x00000010 {
		t.Errorf("ack = %#x, want %#x — the ack must follow the peer through the rollover", ack, 0x00000010)
	}

	// Serial arithmetic: when the peer starts a whole new flow (its own ISN), the
	// large step reads as forward motion and must be adopted, not ignored.
	s = newSeqState(SeqRealistic)
	s.observe(0xFFFFFF00, 16, 0, false) // ack -> 0xFFFFFF10
	s.observe(0x20000000, 8, 0, false)  // peer restarted at a fresh ISN
	if _, ack, _ := s.next(1); ack != 0x20000008 {
		t.Errorf("ack = %#x, want %#x after the peer restarted", ack, 0x20000008)
	}

	// A fixed-mode flow is unaffected: still the constant pair.
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()
	if _, err := c.WriteTo([]byte("x"), c.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	if h := parseHeader(t, <-f.sent); h.seq != carrierSeq || h.ack != carrierAck {
		t.Errorf("fixed mode: seq/ack = %d/%d, want 1/1", h.seq, h.ack)
	}
}

// TestRandomISNCoversTheFullRange: an ISN must be uniform over all 32 bits. A
// restricted range is invisible in one flow but a fingerprint across many — an
// earlier version drew from the low half only, so no flow ever set the top bit,
// which no real stack does. Checked statistically: over 4096 draws the top bit
// should be set roughly half the time, and the values should spread across all
// four quarters of the space.
func TestRandomISNCoversTheFullRange(t *testing.T) {
	const draws = 4096
	var topBitSet int
	quarters := map[uint32]int{}
	for i := 0; i < draws; i++ {
		isn := randomISN()
		if isn == 0 {
			t.Fatal("ISN 0 must never be produced")
		}
		if isn&0x80000000 != 0 {
			topBitSet++
		}
		quarters[isn>>30]++
	}

	// Binomial(4096, 0.5) has sd 32; +/-8 sd is 1728..2368. A range-restricted
	// generator lands at 0 or 4096, so this is a wide margin around a huge signal.
	if topBitSet < 1728 || topBitSet > 2368 {
		t.Errorf("top bit set in %d of %d ISNs; want ~half — the range looks restricted", topBitSet, draws)
	}
	if len(quarters) != 4 {
		t.Errorf("ISNs only landed in %d of the 4 quarters of the sequence space: %v", len(quarters), quarters)
	}
	for q, n := range quarters {
		if n < draws/8 {
			t.Errorf("quarter %d got only %d of %d draws; want ~%d", q, n, draws, draws/4)
		}
	}
}

// TestSeqWrapsLikeRealTCP: at 2^32 the sequence rolls over and the stream carries
// on, exactly as TCP defines it — 4.29 GB into a transfer is not a reason to
// disturb the flow. The crucial property is the SECOND assertion group: measured
// in serial arithmetic (RFC 1982), the step across the rollover is just the bytes
// sent, which is what a window-tracking middlebox sees. An earlier version jumped
// back to the ISN here, which reads as a multi-gigabyte forward leap and gets the
// flow dropped as out-of-window.
func TestSeqWrapsLikeRealTCP(t *testing.T) {
	s := newSeqState(SeqRealistic)
	s.seq = 0xFFFFFFF0 // 16 bytes of sequence space left before the rollover

	first, _, _ := s.next(10)  // 0xFFFFFFF0, leaves 0xFFFFFFFA
	second, _, _ := s.next(10) // 0xFFFFFFFA, leaves 0x00000004 (rolled over)
	third, _, _ := s.next(10)  // 0x00000004

	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"before the rollover", first, 0xFFFFFFF0},
		{"at the rollover", second, 0xFFFFFFFA},
		{"after the rollover", third, 0x00000004},
	} {
		if c.got != c.want {
			t.Errorf("seq %s = %#x, want %#x", c.name, c.got, c.want)
		}
	}

	// Continuity is what matters: every step is exactly the bytes sent, including
	// the one that crosses 2^32.
	if d := int32(second - first); d != 10 {
		t.Errorf("step before the rollover = %d, want 10", d)
	}
	if d := int32(third - second); d != 10 {
		t.Errorf("step ACROSS the rollover = %d, want 10 — the wrap must be a normal forward step", d)
	}

	// And it keeps going afterwards, rather than being a one-off.
	fourth, _, _ := s.next(1400)
	if d := int32(fourth - third); d != 10 {
		t.Errorf("step after the rollover = %d, want 10", d)
	}
	if fifth, _, _ := s.next(1); int32(fifth-fourth) != 1400 {
		t.Errorf("step = %d, want 1400", int32(fifth-fourth))
	}
}

// TestSeqRollsOverOnTheWire drives the rollover through the real send path and
// reads the sequence numbers back off the crafted packets, so the guarantee is
// checked where it matters rather than only inside seqState.
func TestSeqRollsOverOnTheWire(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	payload := []byte("0123456789") // 10 bytes per packet
	c.clientSeq.mu.Lock()
	c.clientSeq.seq = 0xFFFFFFF5 // 11 bytes short of the rollover
	c.clientSeq.mu.Unlock()

	var seqs []uint32
	for i := 0; i < 4; i++ {
		if _, err := c.WriteTo(payload, c.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, parseHeader(t, <-f.sent).seq)
	}

	want := []uint32{0xFFFFFFF5, 0xFFFFFFFF, 0x00000009, 0x00000013}
	for i := range want {
		if seqs[i] != want[i] {
			t.Errorf("packet %d seq = %#x, want %#x", i, seqs[i], want[i])
		}
	}
	for i := 1; i < len(seqs); i++ {
		if d := int32(seqs[i] - seqs[i-1]); d != 10 {
			t.Errorf("packet %d: step = %d, want the 10 bytes sent", i, d)
		}
	}
	t.Logf("on the wire across 2^32: %#x -> %#x -> %#x -> %#x", seqs[0], seqs[1], seqs[2], seqs[3])
}

// TestSeqSurvivesAFullLap walks the counter all the way around 2^32 and checks it
// lands where TCP says it should, with no discontinuity anywhere.
func TestSeqSurvivesAFullLap(t *testing.T) {
	s := newSeqState(SeqRealistic)
	start, _, _ := s.next(0)

	const step = 1 << 20 // 1 MiB at a time: 4096 laps steps == exactly 2^32
	prev := start
	for i := 0; i < 1<<12; i++ {
		s.next(step)
		cur, _, _ := s.next(0)
		if d := int32(cur - prev); d != step {
			t.Fatalf("iteration %d: step = %d, want %d (discontinuity at %#x)", i, d, step, cur)
		}
		prev = cur
	}
	if prev != start {
		t.Errorf("after exactly 2^32 bytes seq = %#x, want to be back at the start %#x", prev, start)
	}
}

// TestFixedSeqMode: the default mode still pins both numbers to 1 (the
// behaviour that keeps window-tracking NAT happy).
func TestFixedSeqMode(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()

	for _, payload := range []string{"aaaa", "bbbbbbbbbbbbbbbb"} {
		if _, err := c.WriteTo([]byte(payload), c.RemoteAddr()); err != nil {
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
		rxDone:   make(chan struct{}),
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
