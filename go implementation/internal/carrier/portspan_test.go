package carrier

import (
	"net"
	"testing"
	"time"
)

// TestClientSpansOnTheWire walks a client through many reconnect rotations and
// checks the ports actually put on the wire: the SOURCE port must stay inside
// client_port_span, while the DESTINATION port sweeps server_port_span. The two
// spans are independent — a narrow client span does not narrow the number of
// server ports contacted, which is easy to misread as "client_port_span is
// ignored" when watching a capture.
func TestClientSpansOnTheWire(t *testing.T) {
	f := newFakeIO()
	c := &Carrier{
		opts: Options{
			Role: RoleClient, VPSIP: net.IPv4(203, 0, 113, 10),
			ServerPort: 45000, ServerPortSpan: 8,
			ClientPort: 40000, ClientPortSpan: 2,
		},
		localIP: net.IPv4(192, 168, 1, 5),
		pio:     f,
		rx:      make(chan rxPacket, 16),
		closed:  make(chan struct{}),
	}
	c.curClientPort.Store(uint32(c.opts.ClientPort))
	c.curServerPort.Store(uint32(c.opts.ServerPort))
	c.peer.Store(&Addr{IP: c.opts.VPSIP, Port: c.opts.ServerPort})
	defer c.Close()

	srcSeen := map[uint16]bool{}
	dstSeen := map[uint16]bool{}
	for i := 0; i < 10; i++ { // more attempts than either span, to catch a leak
		if _, err := c.WriteTo([]byte("x"), c.RemoteAddr()); err != nil {
			t.Fatalf("WriteTo #%d: %v", i, err)
		}
		seg, ok := parseIPv4(<-f.sent)
		if !ok {
			t.Fatalf("could not parse injected packet #%d", i)
		}
		srcSeen[seg.srcPort] = true
		dstSeen[seg.dstPort] = true
		c.RotateClientPort()
		c.RotateServerPort()
	}

	for p := range srcSeen {
		if p < 40000 || p >= 40000+2 {
			t.Errorf("source port %d escaped client_port_span [40000,40002)", p)
		}
	}
	if len(srcSeen) != 2 {
		t.Errorf("used %d source ports, want the whole span of 2", len(srcSeen))
	}
	for p := range dstSeen {
		if p < 45000 || p >= 45000+8 {
			t.Errorf("destination port %d escaped server_port_span [45000,45008)", p)
		}
	}
	if len(dstSeen) != 8 {
		t.Errorf("targeted %d server ports, want the whole span of 8", len(dstSeen))
	}
}

// TestRemoteAddrFollowsRotation is load-bearing, not cosmetic. The transport
// (kcp-go) drops any inbound packet whose source address differs from the address
// it was dialled with:
//
//	} else if addr.String() != srcStr { InErrs++; continue }
//
// ReadFrom reports RemoteAddr as that source, so RemoteAddr must move with the
// rotated server port AND callers must dial what it reports. Pin it to the base
// port while dialling a rotated one and the tunnel connects to nothing, silently.
func TestRemoteAddrFollowsRotation(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRealistic) // server 45000, span 4
	defer c.Close()

	for i, want := range []uint16{45000, 45001, 45002, 45003, 45000} {
		got := c.RemoteAddr()
		if got.Port != want {
			t.Errorf("rotation %d: RemoteAddr port = %d, want %d", i, got.Port, want)
		}
		if !got.IP.Equal(c.opts.VPSIP) {
			t.Errorf("rotation %d: RemoteAddr IP = %v, want %v", i, got.IP, c.opts.VPSIP)
		}

		// The address ReadFrom hands the transport must be the same string, or the
		// transport discards the reply.
		pkt, err := testSegment(c.opts.VPSIP, c.localIP, want, uint16(c.curClientPort.Load()),
			1, 1, DefaultTCPFlags(), []byte("from server"))
		if err != nil {
			t.Fatal(err)
		}
		f.inbound <- pkt
		buf := make([]byte, 2048)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, from, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("rotation %d: ReadFrom: %v", i, err)
		}
		if from.String() != got.String() {
			t.Errorf("rotation %d: ReadFrom reported %s but RemoteAddr says %s — the transport would drop this packet",
				i, from, got)
		}

		c.RotateServerPort()
	}
}
