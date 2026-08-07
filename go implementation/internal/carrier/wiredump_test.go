package carrier

import (
	"testing"
	"time"
)

// TestDumpRealisticStream prints the header fields of an actual realistic-mode
// exchange, so the "does this look like a real TCP stream" question can be
// answered by reading it rather than by reasoning about the code.
func TestDumpRealisticStream(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	// send reports the header the way a capture would show it, options included.
	send := func(payload, note string) tcpHeader {
		if _, err := c.WriteTo([]byte(payload), c.peer); err != nil {
			t.Fatal(err)
		}
		pkt := <-f.sent
		h := parseHeader(t, pkt)
		val, ecr := timestampsOf(t, pkt)
		t.Logf("  seq=%-10d ack=%-10d win=%d tsval=%-10d tsecr=%-10d len=%-3d %s",
			h.seq, h.ack, tcpWindow(t, pkt), val, ecr, h.payloadLen, note)
		return h
	}
	// recv delivers a server packet carrying its own timestamp, as a matched
	// realistic peer would.
	recv := func(peerSeq, peerTS uint32, payload string) {
		ts := tcpTimestamps{val: peerTS, ecr: 4242}
		pkt, err := craftSegment(segmentSpec{
			srcIP: c.opts.VPSIP, dstIP: c.localIP,
			srcPort: 45000, dstPort: 40000,
			seq: peerSeq, ack: 1,
			flags:   DefaultTCPFlags(),
			window:  maxWindow,
			ts:      &ts,
			payload: []byte(payload),
		})
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

	t.Log("client -> server, before the server has said anything (ack and tsecr are guesses):")
	send("hello", "")
	send("more data here", "")

	const peerISN, peerTS = uint32(3221225472), uint32(918273645)
	t.Logf("server -> client arrives: 40 bytes at seq %d, tsval %d", peerISN, peerTS)
	recv(peerISN, peerTS, "0123456789012345678901234567890123456789")

	t.Log("client -> server, now acking and echoing the server for real:")
	send("x", "<- ack = peer seq + 40, tsecr = peer tsval")

	t.Log("a late/reordered server packet must not pull either value back:")
	recv(peerISN-1000, peerTS-500, "stale")
	send("y", "<- unchanged")

	t.Log("more server data advances them again:")
	time.Sleep(12 * time.Millisecond) // let our own clock tick
	recv(peerISN+40, peerTS+12, "next chunk")
	h := send("z", "<- ack +10, tsecr +12, our tsval ticked")

	if h.ack != peerISN+50 {
		t.Errorf("final ack = %d, want %d", h.ack, peerISN+50)
	}
}

// TestDumpFixedStream is the same exchange in the default mode, for contrast:
// constant numbers, constant window, no options at all.
func TestDumpFixedStream(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()

	for _, p := range []string{"hello", "more data here"} {
		if _, err := c.WriteTo([]byte(p), c.peer); err != nil {
			t.Fatal(err)
		}
		pkt := <-f.sent
		h := parseHeader(t, pkt)
		t.Logf("  seq=%-10d ack=%-10d win=%d tsval=%-10s tsecr=%-10s len=%d",
			h.seq, h.ack, tcpWindow(t, pkt), "-", "-", h.payloadLen)
	}
}
