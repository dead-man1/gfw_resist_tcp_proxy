package carrier

import (
	"testing"
	"time"
)

// TestRandomModeHoldsSequenceStill is the whole point of the mode, and the reason
// it exists at all.
//
// Measured on a live path: seq_mode realistic died within seconds because a
// middlebox drops anything more than one unscaled window (65535 bytes) past the
// peer's last ack, and — since no SYN is ever sent — no window scale can ever be
// negotiated to raise that. Random mode sidesteps the arithmetic entirely by
// never moving: the gap between our seq and the peer's ack is permanently zero,
// so there is nothing to exceed and no cap on throughput.
//
// If this test ever fails because seq advanced, the mode has silently become
// realistic and will die on a real link.
func TestRandomModeHoldsSequenceStill(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	send := func(payload string) tcpHeader {
		if _, err := c.WriteTo([]byte(payload), c.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		return parseHeader(t, <-f.sent)
	}

	first := send("x")
	if first.seq == 0 {
		t.Error("seq 0 is the one value a real stream never sits at")
	}
	if first.seq == carrierSeq {
		t.Error("seq is 1 — that is fixed mode's signature, which random mode exists to remove")
	}

	// Payloads of wildly different sizes, which in realistic mode would move seq
	// by their combined length (over 8 KB).
	for _, p := range []string{"a", "bb", string(make([]byte, 1000)), "cc", string(make([]byte, 7000))} {
		if h := send(p); h.seq != first.seq {
			t.Fatalf("seq moved from %d to %d after sending %d bytes; random mode must hold it",
				first.seq, h.seq, len(p))
		}
	}
}

// TestRandomModeStillLooksReal: holding seq still must not cost the camouflage.
// Every per-packet tell fixed mode has — seq/ack of 1, a constant window, a bare
// 20-byte header — has to be gone, or the mode is pointless.
func TestRandomModeStillLooksReal(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	send := func() []byte {
		if _, err := c.WriteTo([]byte("payload"), c.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		return <-f.sent
	}

	pkt := send()
	h := parseHeader(t, pkt)
	if h.seq == carrierSeq || h.ack == carrierAck {
		t.Errorf("seq/ack = %d/%d; neither may be the fixed-mode constant", h.seq, h.ack)
	}
	val1, ecr1 := timestampsOf(t, pkt) // also asserts the option is well-formed
	if val1 == 0 || ecr1 == 0 {
		t.Errorf("timestamps = %d/%d; both must be plausible", val1, ecr1)
	}
	if got := TCPOptionBytes(SeqRandom); got != tsOptionLen {
		t.Errorf("TCPOptionBytes(random) = %d, want %d — the payload budget must account for the option", got, tsOptionLen)
	}

	// The clock keeps running even though the sequence number does not. That is
	// not a contradiction: a stack retransmitting one segment sends exactly this,
	// the same seq with a fresh TSval, which is what makes the flow read as
	// retransmissions rather than as a frozen header.
	time.Sleep(15 * time.Millisecond)
	if val2, _ := timestampsOf(t, send()); val2 <= val1 {
		t.Errorf("TSval did not advance over 15ms: %d then %d", val1, val2)
	}

	windows := map[uint16]bool{}
	for i := 0; i < 200; i++ {
		w := tcpWindow(t, send())
		if w < minWindow || w > maxWindow {
			t.Fatalf("window %d outside the intended band [%d, %d]", w, minWindow, maxWindow)
		}
		windows[w] = true
	}
	if len(windows) < 40 {
		t.Errorf("only %d distinct windows in 200 packets — too regular to look real", len(windows))
	}
}

// TestRandomModeAdoptsThenHoldsTheAck. Before the peer speaks we ack a random
// guess, which is unavoidable (there is no SYN-ACK to learn its position from)
// but not something to keep sending: a middlebox cannot reconcile it with
// anything the peer has actually sent. So the first inbound packet replaces it
// outright — and then, unlike realistic mode, it stays put, because the peer's
// own seq is standing still too.
func TestRandomModeAdoptsThenHoldsTheAck(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	ackOf := func() uint32 {
		if _, err := c.WriteTo([]byte("x"), c.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		return parseHeader(t, <-f.sent).ack
	}

	guess := ackOf()

	const peerSeq = 0x4B1D0000
	feedFromServer(t, c, f, peerSeq, "hello") // 5 bytes
	adopted := ackOf()
	if adopted == guess {
		t.Fatal("the ack was not adopted from the peer's first packet; we would keep acking a number it never sent")
	}
	if want := uint32(peerSeq + 5); adopted != want {
		t.Errorf("ack = %d, want the peer's seq + payload = %d", adopted, want)
	}

	// Further packets from a random-mode peer repeat its seq. Our ack must not
	// drift: it is already exactly where that peer's stream ends.
	for _, payload := range []string{"hello", "worldly", "x"} {
		feedFromServer(t, c, f, peerSeq, payload)
		if got := ackOf(); got != adopted {
			t.Errorf("ack moved to %d after a repeat packet; want it held at %d", got, adopted)
		}
	}
}

// TestRandomModeRedrawsPerTuple: a port rotation is a new connection to every
// middlebox on the path, so it must open at a new ISN rather than reusing the one
// a stale entry may still remember.
func TestRandomModeRedrawsPerTuple(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	seqOf := func() uint32 {
		if _, err := c.WriteTo([]byte("x"), c.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		return parseHeader(t, <-f.sent).seq
	}

	seen := map[uint32]bool{seqOf(): true}
	for i := 0; i < 6; i++ {
		c.RotateClientPort()
		c.RotateServerPort()
		s := seqOf()
		if seen[s] {
			t.Errorf("rotation %d reused ISN %d; every tuple needs its own", i, s)
		}
		seen[s] = true
	}
}

// TestNoInFlightLimitWhenSeqIsStill: the send-window clamp is the price of an
// advancing seq, and only realistic mode pays it. Charging it to the other two
// would cost real throughput for no reason.
func TestNoInFlightLimitWhenSeqIsStill(t *testing.T) {
	for _, mode := range []SeqMode{SeqFixed, SeqRandom, SeqMode("")} {
		if got := InFlightLimit(mode); got != 0 {
			t.Errorf("InFlightLimit(%q) = %d, want 0 (no ceiling applies)", mode, got)
		}
	}
	limit := InFlightLimit(SeqRealistic)
	if limit <= 0 || limit >= minWindow {
		t.Errorf("InFlightLimit(realistic) = %d, want a positive value below the %d window it must fit inside",
			limit, minWindow)
	}
}
