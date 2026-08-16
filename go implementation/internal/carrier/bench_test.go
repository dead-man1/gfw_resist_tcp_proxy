package carrier

import (
	"net"
	"testing"
)

// benchIO replays one pre-built packet up to limit times, then parks. It lets a
// benchmark drive the real receive loop (capture -> parse -> filter -> queue)
// without touching a NIC.
type benchIO struct {
	pkt   []byte
	n     int
	limit int
	done  chan struct{}
	park  chan struct{}
}

func newBenchIO(pkt []byte, limit int) *benchIO {
	return &benchIO{pkt: pkt, limit: limit, done: make(chan struct{}), park: make(chan struct{})}
}

func (b *benchIO) Capture() ([]byte, error) {
	if b.n >= b.limit {
		select {
		case <-b.done:
		default:
			close(b.done) // every packet has been handed over
		}
		<-b.park // block instead of spinning; Close releases us
		return nil, net.ErrClosed
	}
	b.n++
	return b.pkt, nil
}

func (b *benchIO) Inject([]byte) error { return nil }

func (b *benchIO) Close() error {
	select {
	case <-b.park:
	default:
		close(b.park)
	}
	return nil
}

func benchPacket(b *testing.B, dstPort uint16, payloadLen int) []byte {
	b.Helper()
	pkt, err := testSegment(net.IPv4(198, 51, 100, 7), net.IPv4(203, 0, 113, 9),
		40000, dstPort, 1, 1, DefaultTCPFlags(), make([]byte, payloadLen))
	if err != nil {
		b.Fatal(err)
	}
	return pkt
}

// BenchmarkParseIPv4 is the cost paid for EVERY packet on the interface, carrier
// or not: the capture backends attach no kernel filter, so all of the host's
// IPv4 traffic reaches this function before the port check can reject it.
func BenchmarkParseIPv4(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		pkt := benchPacket(b, 45000, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := parseIPv4(pkt); !ok {
					b.Fatal("parse failed")
				}
			}
		})
	}
}

// BenchmarkRecvLoopReject measures the whole path for traffic that is NOT ours —
// the common case on a busy VPS, where every SSH/HTTPS/backend packet is captured,
// parsed, and dropped on the port check.
func BenchmarkRecvLoopReject(b *testing.B) {
	pkt := benchPacket(b, 49152, 1400) // outside the server span => rejected
	f := newBenchIO(pkt, b.N)
	c := &Carrier{
		opts:     Options{Role: RoleServer, ServerPort: 45000, ServerPortSpan: 8},
		pio:      f,
		tcpFlags: DefaultTCPFlags(),
		rx:       make(chan rxPacket, 1024),
		closed:   make(chan struct{}),
		rxDone:   make(chan struct{}),
	}
	c.curServerPort.Store(uint32(c.opts.ServerPort))
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	go c.recvLoop()
	<-f.done
	b.StopTimer()
	c.Close()
}

// BenchmarkRecvLoopAccept measures the carrier-traffic path: parse, port match,
// payload copy, and hand-off to the transport via ReadFrom.
func BenchmarkRecvLoopAccept(b *testing.B) {
	pkt := benchPacket(b, 45000, 1400)
	f := newBenchIO(pkt, b.N)
	c := &Carrier{
		opts:     Options{Role: RoleServer, ServerPort: 45000, ServerPortSpan: 8},
		pio:      f,
		tcpFlags: DefaultTCPFlags(),
		rx:       make(chan rxPacket, 1024),
		closed:   make(chan struct{}),
		rxDone:   make(chan struct{}),
	}
	c.curServerPort.Store(uint32(c.opts.ServerPort))
	buf := make([]byte, 2048)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	go c.recvLoop()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	c.Close()
}

// BenchmarkCraftSegment is the send-side cost per packet (serialize + checksums).
func BenchmarkCraftSegment(b *testing.B) {
	src, dst := net.IPv4(192, 168, 1, 5), net.IPv4(203, 0, 113, 10)
	payload := make([]byte, 1400)
	flags := DefaultTCPFlags()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := testSegment(src, dst, 40000, 45000, 1, 1, flags, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCraftSegmentRealistic is the same, with everything realistic mode adds
// to the header: a jittered window and the 12-byte timestamp option.
func BenchmarkCraftSegmentRealistic(b *testing.B) {
	src, dst := net.IPv4(192, 168, 1, 5), net.IPv4(203, 0, 113, 10)
	payload := make([]byte, 1400-tsOptionLen)
	flags := DefaultTCPFlags()
	s := newSeqState(SeqRealistic)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		seq, ack, ts := s.next(uint32(len(payload)))
		_, err := craftSegment(segmentSpec{
			srcIP: src, dstIP: dst,
			srcPort: 40000, dstPort: 45000,
			seq: seq, ack: ack,
			flags:   flags,
			window:  randomWindow(),
			ts:      &ts,
			payload: payload,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSeqStateNext is the extra bookkeeping seq_mode: realistic adds per
// sent packet (sequence arithmetic plus the timestamp clock read).
func BenchmarkSeqStateNext(b *testing.B) {
	s := newSeqState(SeqRealistic)
	for i := 0; i < b.N; i++ {
		s.next(1400)
	}
}

// BenchmarkRandomWindow is the per-packet window jitter.
func BenchmarkRandomWindow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		randomWindow()
	}
}

func sizeName(n int) string {
	switch n {
	case 64:
		return "64B"
	case 576:
		return "576B"
	default:
		return "1400B"
	}
}
