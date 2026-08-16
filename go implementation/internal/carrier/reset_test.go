package carrier

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSendResetSendsBareReset pins the packet that frees a stuck tuple: a
// standalone RST on the carrier 4-tuple, carrying nothing else. The shape matters
// — a middlebox keys its entry on the tuple, and anything that made this look like
// carrier data instead of a reset would fail to clear it.
func TestSendResetSendsBareReset(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	if err := c.SendReset(); err != nil {
		t.Fatalf("SendReset: %v", err)
	}
	pkt := <-f.sent

	seg, ok := parseIPv4(pkt)
	if !ok {
		t.Fatal("could not parse the reset")
	}
	if len(seg.payload) != 0 {
		t.Errorf("reset carries %d payload bytes, want none", len(seg.payload))
	}
	if !seg.srcIP.Equal(c.localIP) || !seg.dstIP.Equal(c.opts.VPSIP) {
		t.Errorf("reset addressed %v -> %v, want %v -> %v", seg.srcIP, seg.dstIP, c.localIP, c.opts.VPSIP)
	}

	h := parseHeader(t, pkt)
	if h.flags&flagRST == 0 {
		t.Errorf("RST bit not set, flags = %08b", h.flags)
	}
	// RST alone: no ACK (this is a reject, not an acknowledgement), and above all
	// no SYN — that is the one bit the whole carrier design avoids.
	for _, b := range []struct {
		bit  byte
		name string
	}{{flagSYN, "SYN"}, {flagACK, "ACK"}, {flagPSH, "PSH"}, {flagURG, "URG"}, {flagFIN, "FIN"}} {
		if h.flags&b.bit != 0 {
			t.Errorf("%s must not be set on the reset, flags = %08b", b.name, h.flags)
		}
	}
	if h.seq != carrierSeq || h.ack != carrierAck {
		t.Errorf("reset seq/ack = %d/%d, want %d/%d", h.seq, h.ack, carrierSeq, carrierAck)
	}
	if w := tcpWindow(t, pkt); w != 0 {
		t.Errorf("reset window = %d, want 0 — a reset leaves nothing to receive into", w)
	}
	if opts := tcpOptions(t, pkt); len(opts) != 0 {
		t.Errorf("reset carries TCP options %x, want none", opts)
	}
}

// TestSendResetNeedsNoOptIn: releasing a tuple is cleanup, not a feature. It has
// to happen on every disconnect, failed attempt and shutdown regardless of
// configuration — the opt-in setting only adds the *before-connect* reset+wait.
func TestSendResetNeedsNoOptIn(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic) // ResetAndWaitBeforeConnect left false
	defer c.Close()

	if err := c.SendReset(); err != nil {
		t.Fatalf("SendReset: %v", err)
	}
	select {
	case <-f.sent:
	case <-time.After(time.Second):
		t.Error("no reset was sent; releasing a tuple must not depend on a config flag")
	}
}

// TestSendResetIsIdenticalInBothModes: the reset is path maintenance, not carrier
// traffic, so realistic mode's sequence numbers, window jitter and timestamps must
// not leak into it. Byte-for-byte equality is the clearest way to say that.
func TestSendResetIsIdenticalInBothModes(t *testing.T) {
	grab := func(mode SeqMode) []byte {
		f := newFakeIO()
		c := newTestClient(f, mode)
		defer c.Close()
		if err := c.SendReset(); err != nil {
			t.Fatalf("SendReset: %v", err)
		}
		return <-f.sent
	}
	fixed, realistic := grab(SeqFixed), grab(SeqRealistic)
	if len(fixed) != len(realistic) {
		t.Fatalf("reset is %d bytes in fixed mode, %d in realistic", len(fixed), len(realistic))
	}
	for i := range fixed {
		if fixed[i] != realistic[i] {
			t.Fatalf("resets differ at byte %d (%#x vs %#x); the reset must not depend on seq_mode",
				i, fixed[i], realistic[i])
		}
	}
}

// TestSendResetTargetsTheTupleInUse: the reset frees the tuple we are letting go
// of, so it must be sent BEFORE rotating away from it. Rotating first would reset
// a port nobody has touched and leave the stuck one stuck.
func TestSendResetTargetsTheTupleInUse(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	type tuple struct{ src, dst uint16 }
	var got []tuple
	for i := 0; i < 3; i++ {
		if err := c.SendReset(); err != nil {
			t.Fatal(err)
		}
		h, _ := parseIPv4(<-f.sent)
		got = append(got, tuple{h.srcPort, h.dstPort})
		c.RotateClientPort()
		c.RotateServerPort()
	}

	// newTestClient: client 40000 span 2, server 45000 span 4.
	want := []tuple{{40000, 45000}, {40001, 45001}, {40000, 45002}}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reset %d went %d->%d, want %d->%d", i, got[i].src, got[i].dst, want[i].src, want[i].dst)
		}
	}
}

// TestSendResetServerIsNoOp: only the client releases tuples. The server is
// passive — it never dials, and it has no single tuple to reset.
func TestSendResetServerIsNoOp(t *testing.T) {
	f := newFakeIO()
	c := newTestServer(nil, f)
	c.opts.ResetAndWaitBeforeConnect = true // even when asked
	defer c.Close()

	if err := c.SendReset(); err != nil {
		t.Fatalf("SendReset: %v", err)
	}
	select {
	case pkt := <-f.sent:
		t.Errorf("the server sent a reset: % x", pkt[:20])
	case <-time.After(100 * time.Millisecond):
	}
}

// TestSendResetAfterClose must not inject onto a closed backend.
func TestSendResetAfterClose(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	c.Close()
	if err := c.SendReset(); err != net.ErrClosed {
		t.Errorf("err = %v, want net.ErrClosed", err)
	}
}

// TestResetAndWaitIsOptIn: the before-connect reset costs resetWait on every
// attempt, so it must do nothing at all unless explicitly enabled.
func TestResetAndWaitIsOptIn(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic) // not enabled
	defer c.Close()

	start := time.Now()
	if err := c.ResetAndWait(context.Background()); err != nil {
		t.Fatalf("ResetAndWait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waited %v while disabled", elapsed)
	}
	select {
	case pkt := <-f.sent:
		t.Errorf("a reset was sent while disabled: % x", pkt[:20])
	case <-time.After(100 * time.Millisecond):
	}
}

// TestResetAndWaitSendsThenWaits: when enabled it must send the reset first and
// then hold for resetWait, which is the whole point — a middlebox keeps the entry
// in a closing state on its own timer, and reusing the tuple before that expires
// is what left the tunnel unable to connect at all.
func TestResetAndWaitSendsThenWaits(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	c.opts.ResetAndWaitBeforeConnect = true
	defer c.Close()

	// Cancel partway through: enough to prove the reset goes out immediately and
	// that the wait is real, without spending resetWait in the test.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.ResetAndWait(ctx)
	elapsed := time.Since(start)

	select {
	case <-f.sent: // the reset must precede the wait, not follow it
	default:
		t.Error("no reset was sent before the wait")
	}
	if err == nil {
		t.Errorf("want the context error after %v; resetWait is %v", elapsed, resetWait)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("returned after %v without waiting", elapsed)
	}
	if elapsed >= resetWait {
		t.Errorf("waited the full %v despite cancellation", resetWait)
	}
}

// TestResetAndWaitLongEnough: the constant has to outlast the common middlebox
// close timer (Linux nf_conntrack_tcp_timeout_close, 10s) or it reintroduces the
// bug it exists to fix.
func TestResetAndWaitLongEnough(t *testing.T) {
	if resetWait <= 10*time.Second {
		t.Errorf("resetWait is %v; it must exceed the 10s conntrack close timeout", resetWait)
	}
}

// TestResetFlagStaysOutOfConfig: RST is reachable in code (SendReset) but must
// never be settable from carrier.tcp_flags, where it would ride on data segments
// and tear down the flow they belong to.
func TestResetFlagStaysOutOfConfig(t *testing.T) {
	for _, name := range []string{"rst", "RST", "reset", " rst "} {
		if _, err := ParseTCPFlags([]string{"ack", name}); err == nil {
			t.Errorf("tcp_flags %q should still be refused", name)
		}
	}
	if DefaultTCPFlags().RST {
		t.Error("the default flags must not set RST")
	}
	if got := DefaultTCPFlags().String(); got != "ack+psh" {
		t.Errorf("DefaultTCPFlags().String() = %q, want ack+psh", got)
	}
	if got := (TCPFlags{RST: true}).String(); got != "rst" {
		t.Errorf("String() = %q, want rst", got)
	}
}

// TestDataSegmentsNeverCarryRST guards the separation from the other side: the
// normal send path must keep emitting data segments with no reset bit.
func TestDataSegmentsNeverCarryRST(t *testing.T) {
	for _, mode := range []SeqMode{SeqFixed, SeqRealistic} {
		f := newFakeIO()
		c := newTestClient(f, mode)
		if _, err := c.WriteTo([]byte("payload"), c.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		h := parseHeader(t, <-f.sent)
		c.Close()
		if h.flags&flagRST != 0 {
			t.Errorf("%s mode: data segment carries RST, flags = %08b", mode, h.flags)
		}
	}
}
