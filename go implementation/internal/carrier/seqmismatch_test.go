package carrier

import (
	"sync"
	"testing"
	"time"
)

// warnRecorder collects the carrier's runtime warnings.
type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnRecorder) warn(msg string, _ ...any) {
	w.mu.Lock()
	w.msgs = append(w.msgs, msg)
	w.mu.Unlock()
}

func (w *warnRecorder) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.msgs)
}

// feedFromServer pushes one server->client packet at the given seq and waits for
// the receive loop to hand it up.
func feedFromServer(t *testing.T, c *Carrier, f *fakeIO, seq uint32, payload string) {
	t.Helper()
	pkt, err := testSegment(c.opts.VPSIP, c.localIP, 45000, 40000, seq, 1, DefaultTCPFlags(), []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	f.inbound <- pkt
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
}

// TestWarnsOnSeqModeMismatch: running realistic against a peer whose seq stands
// still reproduces the NAT death (our seq climbs past a ceiling the peer's
// settled ack never raises). It must be reported, not silently endured.
//
// The peer's constant is a parameter because the detector must catch BOTH
// non-advancing modes: fixed sits at seq 1, random sits at its own random ISN.
// Nothing may key on the value.
func TestWarnsOnSeqModeMismatch(t *testing.T) {
	for _, peerSeq := range []uint32{carrierSeq, 0x9E3779B9} {
		w := &warnRecorder{}
		f := newFakeIO()
		c := newTestClient(f, SeqRealistic)
		c.warn = w.warn

		// One packet establishes where the peer is; only repeats are evidence that
		// it is not moving, so the warning cannot fire before the fourth.
		for i, label := range []string{"a", "b", "c"} {
			feedFromServer(t, c, f, peerSeq, label)
			if w.count() != 0 {
				t.Errorf("peer_seq=%#x: warned after %d packets, too little evidence: %v", peerSeq, i+1, w.msgs)
			}
		}
		feedFromServer(t, c, f, peerSeq, "d")
		if w.count() != 1 {
			t.Fatalf("peer_seq=%#x: want exactly one warning once the seq has clearly frozen, got %d: %v",
				peerSeq, w.count(), w.msgs)
		}

		// However long the mismatch persists, the operator is told once.
		for i := 0; i < 5; i++ {
			feedFromServer(t, c, f, peerSeq, "e")
		}
		if w.count() != 1 {
			t.Errorf("peer_seq=%#x: warning should fire once, got %d", peerSeq, w.count())
		}
		c.Close()
	}
}

// TestNoWarnWhenWeDoNotAdvance: the warning is about OUR seq outrunning the
// peer's ack, so it is meaningless unless our seq moves. In random mode both ends
// stand still, which is a consistent pairing and must stay silent.
func TestNoWarnWhenWeDoNotAdvance(t *testing.T) {
	w := &warnRecorder{}
	f := newFakeIO()
	c := newTestClient(f, SeqRandom)
	c.warn = w.warn
	defer c.Close()

	for i := 0; i < 8; i++ {
		feedFromServer(t, c, f, 0x5A5A5A5A, "x")
	}
	if w.count() != 0 {
		t.Errorf("random+random is a valid pairing, got %v", w.msgs)
	}
}

// TestNoWarnForRealisticPeer: a properly configured peer must never trip the
// detector, however its ISN happens to fall.
func TestNoWarnForRealisticPeer(t *testing.T) {
	for _, isn := range []uint32{1, 2, 1000, 1 << 30, 0xFFFFFF00} {
		w := &warnRecorder{}
		f := newFakeIO()
		c := newTestClient(f, SeqRealistic)
		c.warn = w.warn

		seq := isn
		for i := 0; i < 8; i++ {
			feedFromServer(t, c, f, seq, "payload")
			seq += 7 // a realistic peer's seq advances with every byte it sends
		}
		c.Close()
		if w.count() != 0 {
			t.Errorf("isn=%d: a realistic peer must not be flagged, got %v", isn, w.msgs)
		}
	}
}

// TestNoWarnInFixedMode: when we are fixed too, the pair is consistent and safe —
// nothing to report.
func TestNoWarnInFixedMode(t *testing.T) {
	w := &warnRecorder{}
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	c.warn = w.warn
	defer c.Close()

	for i := 0; i < 5; i++ {
		feedFromServer(t, c, f, carrierSeq, "x")
	}
	if w.count() != 0 {
		t.Errorf("fixed+fixed is a valid pairing, got %v", w.msgs)
	}
}

// TestMismatchDetectorResets: an isolated seq==1 packet from an otherwise
// realistic peer (its ISN could legitimately be 1 for exactly one packet) must
// not accumulate toward the warning.
func TestMismatchDetectorResets(t *testing.T) {
	w := &warnRecorder{}
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	c.warn = w.warn
	defer c.Close()

	for i := 0; i < 6; i++ {
		feedFromServer(t, c, f, carrierSeq, "x") // looks fixed...
		feedFromServer(t, c, f, 500000, "x")     // ...but then advances, so reset
	}
	if w.count() != 0 {
		t.Errorf("alternating seqs are not a frozen peer, got %v", w.msgs)
	}
}

// TestWarnOptionalWhenUnset: the detector must be inert when no callback is
// wired (the carrier has no logger of its own).
func TestWarnOptionalWhenUnset(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	c.warn = nil
	defer c.Close()
	for i := 0; i < 5; i++ {
		feedFromServer(t, c, f, carrierSeq, "x") // must not panic
	}
}
