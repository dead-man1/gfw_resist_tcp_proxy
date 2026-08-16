package carrier

import (
	"strings"
	"testing"
	"time"
)

// silentFor backdates the last-receive marker so the wedge conditions can be
// exercised without spending wedgeSilence in the test.
func silentFor(c *Carrier, d time.Duration) {
	c.lastRxNanos.Store(time.Now().Add(-d).UnixNano())
}

// sendBytes pushes n bytes through the carrier so bytesOut climbs.
func sendBytes(t *testing.T, c *Carrier, n int) {
	t.Helper()
	if _, err := c.WriteTo(make([]byte, n), c.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
}

// TestWedgedNeedsBothSilenceAndTraffic is the guard on a detector that tears down
// a working tunnel if it is too eager.
//
// The failure it exists to catch: a middlebox starts discarding one direction of
// the carrier tuple, so we transmit into a hole while the transport waits out its
// keepalive — ~16s of a session that is "up" and can never recover, because only
// a port rotation clears the middlebox's state. Neither condition alone is
// evidence: silence is what an idle tunnel looks like, and a burst of sent bytes
// is what a healthy one looks like.
func TestWedgedNeedsBothSilenceAndTraffic(t *testing.T) {
	cases := []struct {
		name    string
		silence time.Duration
		bytes   int
		want    bool
	}{
		{"healthy: recent traffic both ways", 0, 4 * wedgeMinBytes, false},
		{"idle: silent but sending nothing", 4 * wedgeSilence, 0, false},
		{"idle-ish: silent, only a keepalive sent", 4 * wedgeSilence, 1 << 10, false},
		{"busy: pushing hard, peer still answering", wedgeSilence / 4, 8 * wedgeMinBytes, false},
		{"wedged: pushing hard into total silence", 2 * wedgeSilence, 2 * wedgeMinBytes, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIO()
			f.drain()
			c := newTestClient(f, SeqRandom)
			defer c.Close()

			// Establish that the tuple worked at some point, then arrange the state.
			c.lastRxNanos.Store(time.Now().UnixNano())
			c.outAtLastRx.Store(c.bytesOut.Load())
			if tc.bytes > 0 {
				sendBytes(t, c, tc.bytes)
			}
			silentFor(c, tc.silence)

			why := c.Wedged()
			if got := why != ""; got != tc.want {
				t.Errorf("Wedged() = %q (wedged=%v), want wedged=%v", why, got, tc.want)
			}
		})
	}
}

// TestWedgedStaysQuietUntilTheTupleHasWorked: a tuple that has never delivered
// anything is a connect that has not completed, which the dial timeout already
// owns. Firing here would abandon ports faster than they can come up.
func TestWedgedQuietBeforeFirstPacket(t *testing.T) {
	f := newFakeIO()
	f.drain()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	sendBytes(t, c, 8*wedgeMinBytes)
	if why := c.Wedged(); why != "" {
		t.Errorf("Wedged() = %q before any inbound packet; connecting is not wedged", why)
	}
}

// TestWedgedIsClientOnly: the server has many tuples and cannot rotate any of
// them, and a client that has simply gone away must not read as a fault.
func TestWedgedIsClientOnly(t *testing.T) {
	f := newFakeIO()
	f.drain()
	c := newTestServer(nil, f)
	defer c.Close()

	c.lastRxNanos.Store(time.Now().Add(-time.Hour).UnixNano())
	c.bytesOut.Add(uint64(100 * wedgeMinBytes))
	if why := c.Wedged(); why != "" {
		t.Errorf("Wedged() = %q on the server role, want it inert", why)
	}
}

// TestWedgedClearsOnRotation: the verdict is about the tuple in use. After a
// rotation there is a new one, and carrying the old tuple's silence across would
// condemn the replacement before it has had a chance to speak.
func TestWedgedClearsOnRotation(t *testing.T) {
	f := newFakeIO()
	f.drain()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	c.lastRxNanos.Store(time.Now().UnixNano())
	c.outAtLastRx.Store(c.bytesOut.Load())
	sendBytes(t, c, 4*wedgeMinBytes)
	silentFor(c, 4*wedgeSilence)
	if c.Wedged() == "" {
		t.Fatal("setup failed: the tuple should read as wedged before rotating")
	}

	c.RotateServerPort()
	if why := c.Wedged(); why != "" {
		t.Errorf("Wedged() = %q on a freshly rotated tuple, want a clean slate", why)
	}
}

// TestWedgedReasonIsActionable: the string goes straight into a log line the user
// will paste when asking why the tunnel keeps reconnecting, so it has to say what
// was observed rather than just "wedged".
func TestWedgedReasonIsActionable(t *testing.T) {
	f := newFakeIO()
	f.drain()
	c := newTestClient(f, SeqRandom)
	defer c.Close()

	c.lastRxNanos.Store(time.Now().UnixNano())
	c.outAtLastRx.Store(c.bytesOut.Load())
	sendBytes(t, c, 200<<10)
	silentFor(c, 5*time.Second)

	why := c.Wedged()
	for _, want := range []string{"5s", "200 KB", "middlebox"} {
		if !strings.Contains(why, want) {
			t.Errorf("reason %q should mention %q", why, want)
		}
	}
}

// TestReceiveResetsTheWedgeClock: one packet arriving is proof the tuple is
// alive, and must clear the silence however long it had been running.
func TestReceiveResetsTheWedgeClock(t *testing.T) {
	f := newFakeIO()
	c := newTestClient(f, SeqRandom)
	defer c.Close()
	go func() {
		for range f.sent { // keep WriteTo from blocking on the fake's channel
		}
	}()

	c.lastRxNanos.Store(time.Now().UnixNano())
	c.outAtLastRx.Store(c.bytesOut.Load())
	sendBytes(t, c, 4*wedgeMinBytes)
	silentFor(c, 4*wedgeSilence)
	if c.Wedged() == "" {
		t.Fatal("setup failed: should read as wedged")
	}

	feedFromServer(t, c, f, 0x1234, "the peer is alive")
	if why := c.Wedged(); why != "" {
		t.Errorf("Wedged() = %q after an inbound packet, want it cleared", why)
	}
}
