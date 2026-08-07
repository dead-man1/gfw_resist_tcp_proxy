package carrier

import (
	"encoding/binary"
	"testing"
	"time"
)

// tcpOptions returns the option bytes of a crafted packet (everything between the
// fixed 20-byte TCP header and the payload).
func tcpOptions(t *testing.T, ipPkt []byte) []byte {
	t.Helper()
	ihl := int(ipPkt[0]&0x0f) * 4
	tcp := ipPkt[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		t.Fatalf("bogus data offset %d", dataOff)
	}
	return tcp[20:dataOff]
}

func tcpWindow(t *testing.T, ipPkt []byte) uint16 {
	t.Helper()
	ihl := int(ipPkt[0]&0x0f) * 4
	return binary.BigEndian.Uint16(ipPkt[ihl+14 : ihl+16])
}

// timestampsOf decodes the NOP,NOP,TS block realistic mode emits.
func timestampsOf(t *testing.T, ipPkt []byte) (val, ecr uint32) {
	t.Helper()
	opts := tcpOptions(t, ipPkt)
	if len(opts) != tsOptionLen {
		t.Fatalf("option block is %d bytes, want %d: %x", len(opts), tsOptionLen, opts)
	}
	// Exactly the layout Linux emits: 01 01 08 0a <tsval> <tsecr>.
	if opts[0] != 1 || opts[1] != 1 || opts[2] != 8 || opts[3] != 10 {
		t.Fatalf("option header = %x, want 01 01 08 0a (NOP NOP TS len=10)", opts[:4])
	}
	return binary.BigEndian.Uint32(opts[4:8]), binary.BigEndian.Uint32(opts[8:12])
}

// TestFixedModeHeaderUnchanged is the regression guard for the promise that fixed
// mode keeps behaving exactly as it did: no options at all, a 20-byte header, and
// the full window on every packet.
func TestFixedModeHeaderUnchanged(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqFixed)
	defer c.Close()

	for i := 0; i < 5; i++ {
		if _, err := c.WriteTo([]byte("payload"), c.peer); err != nil {
			t.Fatal(err)
		}
		pkt := <-f.sent
		if opts := tcpOptions(t, pkt); len(opts) != 0 {
			t.Errorf("fixed mode must send no TCP options, got %x", opts)
		}
		ihl := int(pkt[0]&0x0f) * 4
		if dataOff := int(pkt[ihl+12]>>4) * 4; dataOff != 20 {
			t.Errorf("fixed mode header is %d bytes, want the bare 20", dataOff)
		}
		if w := tcpWindow(t, pkt); w != maxWindow {
			t.Errorf("fixed mode window = %d, want the constant %d", w, maxWindow)
		}
		if h := parseHeader(t, pkt); h.seq != carrierSeq || h.ack != carrierAck {
			t.Errorf("fixed mode seq/ack = %d/%d, want 1/1", h.seq, h.ack)
		}
	}
	if got := TCPOptionBytes(SeqFixed); got != 0 {
		t.Errorf("TCPOptionBytes(fixed) = %d, want 0", got)
	}
}

// TestRealisticModeAddsTimestamps: the option must be present, well-formed, and
// its clock must advance with real time while staying inside one flow.
func TestRealisticModeAddsTimestamps(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	send := func() []byte {
		if _, err := c.WriteTo([]byte("payload"), c.peer); err != nil {
			t.Fatal(err)
		}
		return <-f.sent
	}

	first := send()
	val1, ecr1 := timestampsOf(t, first)
	if val1 == 0 {
		t.Error("TSval should never be 0 on an established-looking segment")
	}
	if ecr1 == 0 {
		t.Error("TSecr should be a plausible guess before the peer speaks, not 0")
	}

	// Same flow, immediately: the clock has ~1 ms granularity so it must not go
	// backwards, and the echo must be stable until the peer sends something.
	val2, ecr2 := timestampsOf(t, send())
	if int32(val2-val1) < 0 {
		t.Errorf("TSval went backwards: %d then %d", val1, val2)
	}
	if ecr2 != ecr1 {
		t.Errorf("TSecr changed without hearing from the peer: %d then %d", ecr1, ecr2)
	}

	// After a real pause the clock must have moved: a frozen TSval across seconds
	// is as much of a tell as a frozen seq.
	time.Sleep(15 * time.Millisecond)
	val3, _ := timestampsOf(t, send())
	if val3 <= val2 {
		t.Errorf("TSval did not advance over 15 ms: %d then %d", val2, val3)
	}

	if got := TCPOptionBytes(SeqRealistic); got != tsOptionLen {
		t.Errorf("TCPOptionBytes(realistic) = %d, want %d", got, tsOptionLen)
	}
}

// TestRealisticModeEchoesPeerTimestamp: TSecr must carry the peer's clock once we
// have seen it, and must not regress when an older packet arrives late.
func TestRealisticModeEchoesPeerTimestamp(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	// An inbound packet carrying the peer's own timestamp option.
	feedTS := func(peerSeq, peerTSVal uint32) {
		ts := tcpTimestamps{val: peerTSVal, ecr: 12345}
		pkt, err := craftSegment(segmentSpec{
			srcIP: c.opts.VPSIP, dstIP: c.localIP,
			srcPort: 45000, dstPort: 40000,
			seq: peerSeq, ack: 1,
			flags:   DefaultTCPFlags(),
			window:  maxWindow,
			ts:      &ts,
			payload: []byte("from server"),
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
	sendEcr := func() uint32 {
		if _, err := c.WriteTo([]byte("x"), c.peer); err != nil {
			t.Fatal(err)
		}
		_, ecr := timestampsOf(t, <-f.sent)
		return ecr
	}

	feedTS(100000, 777000)
	if got := sendEcr(); got != 777000 {
		t.Errorf("TSecr = %d, want the peer's TSval 777000", got)
	}
	feedTS(100011, 777050)
	if got := sendEcr(); got != 777050 {
		t.Errorf("TSecr = %d, want the peer's newer TSval 777050", got)
	}
	// A late packet with an older clock must not drag the echo back.
	feedTS(100022, 776000)
	if got := sendEcr(); got != 777050 {
		t.Errorf("TSecr = %d, want it to hold at 777050 for a reordered packet", got)
	}
}

// TestPeerWithoutTimestampsIsTolerated: a peer that sends no option (an older
// build, or one in fixed mode) must not break us — we keep our own clock and the
// guessed echo.
func TestPeerWithoutTimestampsIsTolerated(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	if _, err := c.WriteTo([]byte("x"), c.peer); err != nil {
		t.Fatal(err)
	}
	_, guessed := timestampsOf(t, <-f.sent)

	feedFromServer(t, c, f, 500000, "no options here") // testSegment sends none
	if _, err := c.WriteTo([]byte("y"), c.peer); err != nil {
		t.Fatal(err)
	}
	val, ecr := timestampsOf(t, <-f.sent)
	if ecr != guessed {
		t.Errorf("TSecr = %d, want the guess %d retained when the peer sends no timestamps", ecr, guessed)
	}
	if val == 0 {
		t.Error("our own TSval must still be sent")
	}
}

// TestRealisticWindowVaries: the window must not be one constant value, but must
// stay in the high band — it doubles as the middlebox's ceiling for the peer's
// sequence numbers, so shrinking it costs real robustness.
func TestRealisticWindowVaries(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic)
	defer c.Close()

	seen := map[uint16]int{}
	const n = 300
	for i := 0; i < n; i++ {
		if _, err := c.WriteTo([]byte("payload"), c.peer); err != nil {
			t.Fatal(err)
		}
		w := tcpWindow(t, <-f.sent)
		if w < minWindow || w > maxWindow {
			t.Fatalf("window %d outside the intended band [%d, %d]", w, minWindow, maxWindow)
		}
		seen[w]++
	}
	if len(seen) < 50 {
		t.Errorf("only %d distinct windows across %d packets — too regular to look real", len(seen), n)
	}
}

// TestOptionBytesComeOutOfThePayloadBudget: the whole point of TCPOptionBytes is
// that an IP packet is the same size in both modes, so switching to realistic
// cannot push a path-MTU-limited link over the edge.
func TestOptionBytesComeOutOfThePayloadBudget(t *testing.T) {
	const mtu = 1400
	fixedTotal := 20 + 20 + (mtu - TCPOptionBytes(SeqFixed))
	realisticTotal := 20 + 20 + tsOptionLen + (mtu - TCPOptionBytes(SeqRealistic))
	if fixedTotal != realisticTotal {
		t.Errorf("IP packet is %d bytes fixed vs %d realistic; the option bytes must come out of the payload",
			fixedTotal, realisticTotal)
	}
}

// TestRealisticPacketSizeOnTheWire proves the above end to end: with the payload
// budget reduced by TCPOptionBytes, both modes emit the same total IP length.
func TestRealisticPacketSizeOnTheWire(t *testing.T) {
	const mtu = 1400
	total := func(mode SeqMode) int {
		f := newFakeIO()
		c := newTestClient(f, mode)
		defer c.Close()
		payload := make([]byte, mtu-TCPOptionBytes(mode))
		if _, err := c.WriteTo(payload, c.peer); err != nil {
			t.Fatal(err)
		}
		return len(<-f.sent)
	}
	if fixed, realistic := total(SeqFixed), total(SeqRealistic); fixed != realistic {
		t.Errorf("IP packet on the wire: %d bytes in fixed mode, %d in realistic; want equal", fixed, realistic)
	}
}
