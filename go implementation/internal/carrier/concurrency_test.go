package carrier

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCloseDuringInjectIsSafe reproduces the Disconnect-while-reconnecting crash:
// the UI goroutine calls Close (which tears the packet backend down — pcap_close on
// Windows) while the transport is still writing and the reconnect loop may be
// sending a reset. Injecting into a closed backend is a use-after-free in native
// code: it does not panic, it takes the process down. Run under -race, this also
// covers the shared serialize buffer the Windows backend injects through.
func TestCloseDuringInjectIsSafe(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		f := newFakeIO()
		f.drain() // keep Inject from blocking on the channel
		c := newTestClient(f, SeqRealistic)

		var wg sync.WaitGroup
		stop := make(chan struct{})

		// The transport's writers.
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					// net.ErrClosed after Close is the expected outcome, not a failure.
					_, _ = c.WriteTo([]byte("payload"), c.RemoteAddr())
				}
			}()
		}
		// The reconnect loop: resets and port rotation.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.SendReset()
				c.RotateClientPort()
				c.RotateServerPort()
			}
		}()

		// Let them get going, then close underneath them, as Disconnect does.
		time.Sleep(time.Millisecond)
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		time.Sleep(time.Millisecond) // keep injecting against the closed carrier
		close(stop)
		wg.Wait()

		if f.injectedAfterClose.Load() {
			t.Fatal("a packet was injected after the backend was closed")
		}
	}
}

// blockingIO models the real capture backends: Capture parks inside the native
// call for a while and — crucially — Close does NOT unblock it. That is exactly
// how pcap_next_ex behaves, and why freeing the handle underneath it faults
// instead of returning an error.
type blockingIO struct {
	captureFor time.Duration

	capturing        atomic.Int32
	closedMidCapture atomic.Bool
	closed           atomic.Bool
}

func (b *blockingIO) Capture() ([]byte, error) {
	b.capturing.Add(1)
	defer b.capturing.Add(-1)
	time.Sleep(b.captureFor) // inside the native call
	if b.closed.Load() {
		// The real backend would have faulted here rather than telling us.
		b.closedMidCapture.Store(true)
	}
	return nil, net.ErrClosed // nothing captured; the loop retries
}

func (b *blockingIO) Inject([]byte) error { return nil }

func (b *blockingIO) Close() error {
	if b.capturing.Load() > 0 {
		b.closedMidCapture.Store(true)
	}
	b.closed.Store(true)
	return nil
}

// TestCloseWaitsForCaptureToLeaveTheBackend is the regression test for the
// observed GUI crash:
//
//	Exception 0xc0000005 ... carrier.pcapT.nextEx / windowsIO.Capture / recvLoop
//
// Disconnect called Close while the receive loop was inside pcap_next_ex, so
// pcap_close freed the handle under it and wpcap.dll faulted. Close must wait for
// the loop to leave the backend before tearing it down.
func TestCloseWaitsForCaptureToLeaveTheBackend(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		f := &blockingIO{captureFor: 15 * time.Millisecond} // ~Npcap's 10ms read timeout
		c := &Carrier{
			opts:   Options{Role: RoleClient, VPSIP: net.IPv4(203, 0, 113, 10), ServerPort: 45000, ClientPort: 40000},
			pio:    f,
			rx:     make(chan rxPacket, 16),
			closed: make(chan struct{}),
			rxDone: make(chan struct{}),
		}
		c.curClientPort.Store(uint32(c.opts.ClientPort))
		c.curServerPort.Store(uint32(c.opts.ServerPort))
		c.peer.Store(&Addr{IP: c.opts.VPSIP, Port: c.opts.ServerPort})
		go c.recvLoop()

		// Land the Close somewhere inside a capture.
		time.Sleep(time.Duration(attempt%15) * time.Millisecond)
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		if f.closedMidCapture.Load() {
			t.Fatal("the backend was closed while the receive loop was still inside it — " +
				"this is the pcap_close/pcap_next_ex fault")
		}
		if f.capturing.Load() != 0 {
			t.Fatal("a capture was still running after Close returned")
		}
	}
}

// TestCloseIsIdempotent: Disconnect can race with the window closing, and both
// paths call stop.
func TestCloseIsIdempotent(t *testing.T) {
	f := newFakeIO()
	f.drain()
	c := newTestClient(f, SeqRealistic)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Close()
		}()
	}
	wg.Wait()
	if f.closes.Load() != 1 {
		t.Errorf("backend closed %d times, want exactly 1", f.closes.Load())
	}
}
