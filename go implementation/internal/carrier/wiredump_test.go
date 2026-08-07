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

	send := func(payload string) tcpHeader {
		if _, err := c.WriteTo([]byte(payload), c.peer); err != nil {
			t.Fatal(err)
		}
		return parseHeader(t, <-f.sent)
	}
	recv := func(peerSeq uint32, payload string) {
		pkt, err := craftSegment(c.opts.VPSIP, c.localIP, 45000, 40000,
			peerSeq, 1, DefaultTCPFlags(), []byte(payload))
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

	t.Log("client -> server, before the server has said anything (ack is a guess):")
	h := send("hello")
	t.Logf("  seq=%-10d ack=%-10d len=%d", h.seq, h.ack, h.payloadLen)
	h = send("more data here")
	t.Logf("  seq=%-10d ack=%-10d len=%d", h.seq, h.ack, h.payloadLen)

	peerISN := uint32(3221225472) // the server's own random ISN
	t.Log("server -> client arrives, 40 bytes at seq", peerISN)
	recv(peerISN, "0123456789012345678901234567890123456789")

	t.Log("client -> server, now acking the server for real:")
	h = send("x")
	t.Logf("  seq=%-10d ack=%-10d len=%d   (ack == peer seq + 40)", h.seq, h.ack, h.payloadLen)

	t.Log("a late/reordered server packet must not pull the ack back:")
	recv(peerISN-1000, "stale")
	h = send("y")
	t.Logf("  seq=%-10d ack=%-10d len=%d", h.seq, h.ack, h.payloadLen)

	t.Log("more server data advances it again:")
	recv(peerISN+40, "next chunk")
	h = send("z")
	t.Logf("  seq=%-10d ack=%-10d len=%d   (ack == peer seq + 40 + 10)", h.seq, h.ack, h.payloadLen)

	if h.ack != peerISN+50 {
		t.Errorf("final ack = %d, want %d", h.ack, peerISN+50)
	}
}

// TestDumpFixedStream is the same exchange in the default mode, for contrast.
func TestDumpFixedStream(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()

	for _, p := range []string{"hello", "more data here"} {
		if _, err := c.WriteTo([]byte(p), c.peer); err != nil {
			t.Fatal(err)
		}
		h := parseHeader(t, <-f.sent)
		t.Logf("  seq=%-10d ack=%-10d len=%d", h.seq, h.ack, h.payloadLen)
	}
}
