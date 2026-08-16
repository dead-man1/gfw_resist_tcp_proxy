package carrier

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Role selects client (single fixed peer) or server (many peers) behaviour.
type Role int

const (
	RoleClient Role = iota
	RoleServer
)

// Options configures a Carrier.
type Options struct {
	Role       Role
	VPSIP      net.IP // client: server's filtered public IP (required); server: optional reply source, auto-derived per client if nil
	ServerPort uint16 // carrier TCP port the server "listens" on
	ClientPort uint16 // carrier TCP source port the client uses (base of the rotation range)
	// ClientPortSpan is how many source ports the client rotates through on
	// reconnect, starting at ClientPort. 1 (or 0) disables rotation.
	ClientPortSpan int
	// ServerPortSpan is how many carrier ports the server accepts (starting at
	// ServerPort) and the client rotates the destination across on reconnect, to
	// escape a middlebox blocking one port. Must match on both ends. 1 disables.
	ServerPortSpan int
	Interface      string // NIC name; empty = auto-detect toward VPSIP
	SnapLen        int    // capture length; defaults applied if 0
	// TCPFlags names the control bits crafted segments carry, straight from
	// config carrier.tcp_flags (ack|psh|urg|fin). Empty = ack+psh. Open parses
	// and rejects syn/rst.
	TCPFlags []string
	// SeqMode is config carrier.seq_mode: "fixed" (seq/ack pinned to 1) or
	// "realistic". Empty = fixed.
	//
	// gfk itself never inspects the peer's numbers, but "realistic" still has to
	// MATCH on both ends: a climbing seq only stays inside a stateful NAT's window
	// because the peer's ack keeps advancing to cover it. Point realistic at a
	// fixed peer and that direction dies once it is a window past the peer's
	// frozen ack. Open wires Warn to catch it at runtime.
	SeqMode string
	// Warn, if set, reports a non-fatal runtime problem (currently: a peer whose
	// seq_mode disagrees with ours). Signature matches slog.Logger.Warn so a
	// caller can pass it straight through.
	Warn func(msg string, args ...any)
	// ResetAndWaitBeforeConnect additionally resets and then blocks for resetWait
	// before every connect attempt. Off by default: SendReset on release already
	// keeps tuples clean without stalling, and this stalls every attempt. It is the
	// recovery path for a tuple poisoned by something else — an older build, a
	// crash, a kill -9 — where no release-time reset was ever sent.
	ResetAndWaitBeforeConnect bool
}

// rxPacket is one received carrier payload plus its source peer.
type rxPacket struct {
	data []byte
	addr *Addr
}

// replySrc is the (IP, port) the server crafts replies from for a given client:
// the exact destination that client addressed it at. Learned per client so the
// client's ingress filter matches and a server port span works.
type replySrc struct {
	ip   net.IP
	port uint16
}

// Carrier is a net.PacketConn over the fake-TCP link.
type Carrier struct {
	opts    Options
	pio     packetIO
	localIP net.IP
	// peer is the client's view of the server: VPSIP plus the server port CURRENTLY
	// targeted, which RotateServerPort moves. It is what ReadFrom reports as the
	// source of every inbound packet, and kcp-go drops any packet whose source does
	// not match the remote address it was dialled with — so this must track the
	// rotation, and callers must dial the address RemoteAddr reports. Atomic because
	// the receive loop reads it while the reconnect loop rotates.
	peer atomic.Pointer[Addr]

	// curClientPort is the client's current carrier source port, rotated across
	// [ClientPort, ClientPort+ClientPortSpan) on reconnect to dodge a KCP session
	// collision with the server's not-yet-expired old session.
	curClientPort atomic.Uint32
	// curServerPort is the server port the client currently targets, rotated
	// across [ServerPort, ServerPort+ServerPortSpan) on reconnect to escape a
	// middlebox that has started dropping a specific port.
	curServerPort atomic.Uint32

	// learnedSrc maps a client addr string -> replySrc (the exact IP+port the
	// client addressed us at), so the server replies from that address.
	learnedSrc sync.Map

	// tcpFlags are the control bits put on crafted segments; seqMode selects how
	// the sequence numbers evolve. Both are parsed once, in Open.
	tcpFlags TCPFlags
	seqMode  SeqMode
	warn     func(msg string, args ...any) // optional; see Options.Warn
	// clientSeq is the single sequence state of the client role; peerSeq holds one
	// *seqState per client for the server role (addr string -> *seqState). Only
	// used when seqMode is SeqRealistic.
	clientSeq *seqState
	peerSeq   sync.Map
	// fixedPeerHits counts consecutive inbound packets that carry the fixed-mode
	// constant seq; warnedPeerFixed makes the resulting warning fire once.
	fixedPeerHits   atomic.Uint32
	warnedPeerFixed atomic.Bool

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	rx     chan rxPacket
	closed chan struct{}
	// rxDone is closed by recvLoop when it returns, so Close knows the receive
	// loop is no longer inside the packet backend. See Close.
	rxDone    chan struct{}
	closeOnce sync.Once
	// ioMu serialises packet injection and keeps Close from tearing the backend
	// down underneath one. See inject.
	ioMu sync.Mutex

	rdMu         sync.Mutex
	readDeadline time.Time
}

// seqState is the fake-TCP sequence bookkeeping for one flow in
// seq_mode: realistic. It makes a capture of the carrier look like an
// established connection: a random ISN, seq advancing by exactly the bytes
// sent, and an ack that tracks what the peer sent.
//
// Wrapping at 2^32 needs no special case, and must not have one. Sequence
// numbers are modulo-2^32 by design (RFC 793): a real connection that transfers
// more than 4.29 GB rolls over and carries on, and everything that tracks TCP
// compares sequence numbers with serial arithmetic (RFC 1982, Linux's
// before()/after(): (int32)(a-b) < 0), for which the rollover is simply the next
// small forward step. Go's uint32 arithmetic already does exactly this, so
// s.seq += n is the whole implementation.
//
// An earlier version restarted at the ISN on rollover instead. That was a bug:
// jumping from ~2^32 back to a random ISN is not a wrap, it is a jump of up to
// 2 GB, which every window-tracking middlebox reads as wildly out of window and
// drops until the tunnel gives up and reconnects. Do not reintroduce it.
type seqState struct {
	mu  sync.Mutex
	seq uint32 // sequence number for the next byte we send; wraps at 2^32
	ack uint32 // what we ack: the peer's last seq + its payload length
	// seen is false until the peer's real sequence position is known. Until then
	// ack holds a plausible guess (see reset); the first inbound packet replaces
	// it outright, and from then on the ack only ever moves forward.
	seen bool

	// Timestamp option state (RFC 7323). tsBase + milliseconds since tsStart is
	// what we advertise: a per-flow random offset over a 1 ms clock, which is how
	// Linux presents its own timestamps. tsEcr is the peer's last TSval, echoed
	// back; like ack it begins as a plausible guess and becomes the truth on the
	// peer's first packet.
	tsBase  uint32
	tsStart time.Time
	tsEcr   uint32
	tsSeen  bool
}

func newSeqState() *seqState {
	s := &seqState{}
	s.reset()
	return s
}

// reset starts a new flow: fresh ISN, fresh ack guess, fresh timestamp base.
// Called when the carrier 4-tuple changes (port rotation on reconnect), because a
// new tuple is a new connection as far as anything on the path is concerned. It is
// NOT called on sequence rollover — see the type comment.
//
// The ack starts at its own random value rather than at 1. We cannot know where
// the peer's sequence space really is until it sends something (there is no
// SYN-ACK to learn it from), and an ack of 1 on an otherwise mid-stream segment
// is exactly the tell realistic mode exists to remove. The guess is only ever on
// the wire until the peer's first packet arrives — one RTT — after which every
// ack we send is the truth.
func (s *seqState) reset() {
	isn, ack := randomISN(), randomISN()
	// A real stack offsets each connection's timestamp clock by a random amount
	// (Linux: tcp_timestamp_offset), so a fresh flow gets a fresh base rather than
	// continuing a global counter that would tie our flows together.
	tsBase, tsEcr, now := rand.Uint32(), rand.Uint32(), time.Now()
	s.mu.Lock()
	s.seq, s.ack, s.seen = isn, ack, false
	s.tsBase, s.tsStart, s.tsEcr, s.tsSeen = tsBase, now, tsEcr, false
	s.mu.Unlock()
}

// next reserves n bytes of sequence space and returns the header numbers for the
// segment carrying them.
func (s *seqState) next(n uint32) (seq, ack uint32, ts tcpTimestamps) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, ack = s.seq, s.ack
	// Modulo 2^32, exactly as TCP defines it: past 4.29 GB this rolls over and the
	// stream continues uninterrupted. No special case — see the type comment.
	s.seq += n
	// A 1 ms clock, wrapping naturally like a real one. Monotonic within the flow
	// because tsStart only moves on reset, which redraws tsBase at the same time.
	// Read under the lock: reset writes tsStart/tsBase together and we must not see
	// a torn pair (a new base against the old start would jump the clock).
	ts = tcpTimestamps{
		val: s.tsBase + uint32(time.Since(s.tsStart).Milliseconds()),
		ecr: s.tsEcr,
	}
	return seq, ack, ts
}

// observe records an inbound segment so our next ack reflects it, the way a real
// receiver's would.
//
// The first inbound packet replaces the guess from reset outright — it must, or a
// guess that happens to sit "after" the peer's real position would freeze the ack
// there, which is the frozen-ack situation that gets a flow window-dropped.
// After that the ack only advances: a real cumulative ack never regresses, so a
// reordered or retransmitted packet must not walk it backwards. The comparison is
// serial-number arithmetic (RFC 1982), so it stays correct across a 2^32 wrap and
// treats the peer's own overflow restart as forward motion.
func (s *seqState) observe(peerSeq uint32, payloadLen int, peerTS uint32, hasTS bool) {
	ack := peerSeq + uint32(payloadLen)
	if ack == 0 {
		ack = 1 // ack 0 does not occur in an established stream
	}
	s.mu.Lock()
	if !s.seen || int32(ack-s.ack) > 0 {
		s.ack, s.seen = ack, true
	}
	// TSecr echoes the peer's clock, under the same rules as the ack: adopt the
	// first real value we see, then follow it forward only (the peer's own clock is
	// monotonic, so a regression means a reordered packet). A peer with no
	// timestamps — an older build, or one in fixed mode — leaves the guess in
	// place, which is the best we can do and harms nothing: no middlebox validates
	// TSecr, and PAWS lives in endpoints we do not have.
	if hasTS && (!s.tsSeen || int32(peerTS-s.tsEcr) > 0) {
		s.tsEcr, s.tsSeen = peerTS, true
	}
	s.mu.Unlock()
}

// randomISN picks an initial sequence number. RFC 6528 wants these
// unpredictable; math/rand/v2 is seeded from the OS and is plenty, since nothing
// security-relevant rests on it (the payload is encrypted by the transport).
func randomISN() uint32 {
	// Uniform across the whole 32-bit space, as RFC 6528 intends. An earlier
	// version drew from the low half only, to leave room to climb before a wrap;
	// the wrap now needs no room (see seqState), and a restricted range is a
	// fingerprint — invisible in any single flow, but a fleet of flows whose ISNs
	// never set the top bit is not something a real stack produces.
	if isn := rand.Uint32(); isn != 0 {
		return isn
	}
	// 1 in 2^32. A real stream does not sit at sequence 0, and it is the one value
	// that would look planted.
	return 1
}

// checkPeerSeqMode warns once if the peer is evidently running seq_mode: fixed
// while we run realistic — the one combination that is worse than either mode on
// its own.
//
// Why it matters: a stateful NAT (Linux conntrack and friends) validates our
// climbing seq against the peer's last ack plus the peer's advertised window. A
// fixed-mode peer acks 1 forever, so that ceiling never moves; roughly one window
// of traffic later — 64 KB, which is ~24 s on a slow link — every packet we send
// is out-of-window and gets dropped. That is the exact failure this project hit
// before fixed mode existed. Realistic mode escapes it only because a realistic
// peer's ack advances to cover what we sent, so both ends must agree.
func (c *Carrier) checkPeerSeqMode(peerSeq uint32) {
	if c.warn == nil || c.warnedPeerFixed.Load() {
		return
	}
	if peerSeq != carrierSeq {
		c.fixedPeerHits.Store(0)
		return
	}
	// Three inbound packets all sitting at seq==1 is a fixed-mode peer, not a
	// coincidence: a realistic peer draws a random ISN and advances it with every
	// payload byte, so it cannot stay there.
	if c.fixedPeerHits.Add(1) >= 3 && c.warnedPeerFixed.CompareAndSwap(false, true) {
		c.warn("peer looks like seq_mode: fixed while this side is realistic — " +
			"set seq_mode the same on both ends, or a stateful NAT will drop this direction " +
			"about one 64 KB window from now")
	}
}

// seqFor returns the sequence state for a peer: the single client-side state, or
// the server's per-client one, created on first use. It takes the addr rather
// than a key string so the client — which has only one flow — never pays for
// formatting one on the receive path.
func (c *Carrier) seqFor(addr *Addr) *seqState {
	if c.opts.Role == RoleClient {
		return c.clientSeq
	}
	key := addr.String()
	if v, ok := c.peerSeq.Load(key); ok {
		return v.(*seqState)
	}
	actual, _ := c.peerSeq.LoadOrStore(key, newSeqState())
	return actual.(*seqState)
}

// flags reports the control bits for crafted segments. The zero value means a
// Carrier built without Open (tests), which gets the ACK+PSH default.
func (c *Carrier) flags() TCPFlags {
	if c.tcpFlags == (TCPFlags{}) {
		return DefaultTCPFlags()
	}
	return c.tcpFlags
}

// packetIO is the platform-specific raw capture/inject backend.
type packetIO interface {
	// Inject sends one fully-formed IPv4 packet (IP header first).
	Inject(ipPacket []byte) error
	// Capture returns the next captured IPv4 packet (IP header first). The
	// returned slice is only valid until the next Capture call.
	Capture() ([]byte, error)
	Close() error
}

// Open constructs a Carrier, brings up the packet backend, and starts the
// receive loop.
func Open(opts Options) (*Carrier, error) {
	if opts.SnapLen == 0 {
		opts.SnapLen = 2048
	}
	if opts.Role == RoleClient && opts.VPSIP == nil {
		return nil, fmt.Errorf("carrier: VPSIP is required for client role")
	}
	flags, err := ParseTCPFlags(opts.TCPFlags)
	if err != nil {
		return nil, fmt.Errorf("carrier: tcp_flags: %w", err)
	}
	seqMode, err := ParseSeqMode(opts.SeqMode)
	if err != nil {
		return nil, fmt.Errorf("carrier: seq_mode: %w", err)
	}

	// localIP selects the NIC to bind capture/inject to; on the client it is also
	// the crafted source IP. On the server the reply source is VPSIP (override) or
	// auto-derived per client, so localIP here only steers interface selection.
	var localIP net.IP
	switch {
	case opts.Role == RoleClient:
		localIP, err = localIPToward(opts.VPSIP)
		if err != nil {
			return nil, fmt.Errorf("carrier: resolve local IP toward %s: %w", opts.VPSIP, err)
		}
	case opts.VPSIP != nil:
		localIP = opts.VPSIP // server, explicit source IP: its NIC owns it
	case opts.Interface != "":
		localIP = nil // server: NIC chosen by name; source IP derived per client
	default:
		// server, no VPSIP and no interface: find the primary egress NIC. Try the
		// default-route source first — connect() to a globally-routable address
		// resolves via the default gateway and sends NO packet, so we just read
		// back the source IP the kernel would use. (A bogon/reserved probe like
		// TEST-NET can fail next-hop resolution on some hosts, e.g. OVH.) If even
		// that fails, fall back to the first up, non-loopback IPv4 interface.
		localIP, err = localIPToward(net.IPv4(8, 8, 8, 8))
		if err != nil || localIP == nil {
			localIP, err = firstGlobalUnicastIPv4()
		}
		if err != nil {
			return nil, fmt.Errorf("carrier: auto-detect default interface (set carrier.interface): %w", err)
		}
	}

	pio, err := newPacketIO(ioParams{
		role:       opts.Role,
		ifaceName:  opts.Interface,
		localIP:    localIP,
		vpsIP:      opts.VPSIP,
		serverPort: opts.ServerPort,
		clientPort: opts.ClientPort,
		snapLen:    opts.SnapLen,
	})
	if err != nil {
		return nil, err
	}

	c := &Carrier{
		opts:     opts,
		pio:      pio,
		localIP:  localIP,
		tcpFlags: flags,
		seqMode:  seqMode,
		warn:     opts.Warn,
		rx:       make(chan rxPacket, 1024),
		closed:   make(chan struct{}),
		rxDone:   make(chan struct{}),
	}
	c.curClientPort.Store(uint32(opts.ClientPort))
	c.curServerPort.Store(uint32(opts.ServerPort))
	if opts.Role == RoleClient {
		c.peer.Store(&Addr{IP: opts.VPSIP, Port: opts.ServerPort})
		c.clientSeq = newSeqState()
	}
	go c.recvLoop()
	return c, nil
}

// LocalIP reports the source IP used for crafted packets.
func (c *Carrier) LocalIP() net.IP { return c.localIP }

// RotateClientPort advances the client's carrier source port within its span so
// the next reconnect looks like a fresh flow to the server, avoiding a stall
// while the server's previous session for the old port times out. No-op on the
// server or when span<=1. Returns the new port. Only the reconnect loop calls
// this (single writer); recvLoop/WriteTo read the value atomically.
func (c *Carrier) RotateClientPort() uint16 {
	if c.opts.Role != RoleClient || c.opts.ClientPortSpan <= 1 {
		return uint16(c.curClientPort.Load())
	}
	base := uint32(c.opts.ClientPort)
	next := base + (c.curClientPort.Load()-base+1)%uint32(c.opts.ClientPortSpan)
	c.curClientPort.Store(next)
	c.resetSeq()
	return uint16(next)
}

// RotateServerPort advances the server port the client targets within its span,
// so a reconnect tries a different carrier port — escaping a middlebox that has
// started dropping the current one. The server accepts the whole span, so no
// coordination is needed. No-op on the server or when span<=1.
func (c *Carrier) RotateServerPort() uint16 {
	if c.opts.Role != RoleClient || c.opts.ServerPortSpan <= 1 {
		return uint16(c.curServerPort.Load())
	}
	base := uint32(c.opts.ServerPort)
	next := base + (c.curServerPort.Load()-base+1)%uint32(c.opts.ServerPortSpan)
	c.curServerPort.Store(next)
	// Keep the reported peer in step. ReadFrom hands this address to the transport
	// as the source of every inbound packet, and kcp-go silently drops packets whose
	// source differs from the address it was dialled with — so a stale peer here
	// would mean a tunnel that never connects on any rotated port.
	c.peer.Store(&Addr{IP: c.opts.VPSIP, Port: uint16(next)})
	c.resetSeq()
	return uint16(next)
}

// RemoteAddr is the server address the client is currently talking to: VPSIP plus
// the rotated server port, not the base one from the config. Dial with this — it
// is also what ReadFrom reports, and the transport requires the two to agree.
// Nil on the server, which has many peers rather than one.
func (c *Carrier) RemoteAddr() *Addr { return c.peer.Load() }

// resetWait is how long ResetAndWait blocks after its reset.
//
// A reset does not delete a middlebox's entry outright: it moves it to a closing
// state that expires on its own timer (Linux: nf_conntrack_tcp_timeout_close, 10s
// by default) and only then goes away. Reuse the tuple inside that window and the
// entry is still there to reject you — and since each attempt would send another
// reset, a short wait means the tunnel never connects at all. 12s clears the
// common 10s timer with margin. Fixed rather than configurable: the useful values
// are "long enough" or "do not do this", and the release-time resets below make
// the whole path unnecessary in normal operation.
const resetWait = 12 * time.Second

// SendReset emits a standalone TCP RST on the carrier 4-tuple currently in use and
// returns immediately. Client role only; on the server it is a no-op.
//
// This is how gfk releases a tuple: it is sent when a session ends, when a connect
// attempt fails, and at shutdown — never before using a tuple, and never during a
// live session. The point of resetting on release is timing. A middlebox keeps its
// entry for the carrier flow long after a session ends (Linux's ESTABLISHED
// timeout is five days) and that entry remembers the old session's sequence
// window. A new session in seq_mode: realistic opens at a fresh random ISN, lands
// nowhere near what the stale entry expects, and every packet is dropped — the
// tuple stays dead across restarts of both ends, because the state is in the
// middle, not in either endpoint. Resetting as we let go of the tuple starts the
// middlebox's close timer immediately, so by the time the port rotation comes back
// around to it, it is long gone. Resetting just before reuse would instead force us
// to sit out that timer (see resetWait).
//
// The packet is what a kernel emits to reject an unknown connection: RST alone, no
// ACK flag, seq and ack at 1, zero window, no options, no payload. Sent in both seq
// modes — fixed mode does not need it, but it is harmless there.
func (c *Carrier) SendReset() error {
	if c.opts.Role != RoleClient {
		return nil
	}
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}

	pkt, err := craftSegment(segmentSpec{
		srcIP: c.localIP, dstIP: c.opts.VPSIP,
		srcPort: uint16(c.curClientPort.Load()),
		dstPort: uint16(c.curServerPort.Load()),
		seq:     carrierSeq,
		ack:     carrierAck,
		flags:   TCPFlags{RST: true},
	})
	if err != nil {
		return err
	}
	if err := c.inject(pkt); err != nil {
		return err
	}
	// Deliberately not counted in bytesOut: this is path maintenance, not tunnel
	// traffic, and it would skew the throughput readout.
	return nil
}

// ResetAndWait sends a reset and then blocks for resetWait, so the tuple is clean
// before it is reused. No-op unless Options.ResetAndWaitBeforeConnect.
//
// This is the recovery path, not the normal one: it exists for a tuple poisoned by
// something that never got to release it — an older build, a crash, a kill -9 — and
// it costs resetWait on every connect attempt. It returns early if ctx is
// cancelled, so shutdown is not held up by the wait.
func (c *Carrier) ResetAndWait(ctx context.Context) error {
	if c.opts.Role != RoleClient || !c.opts.ResetAndWaitBeforeConnect {
		return nil
	}
	if err := c.SendReset(); err != nil {
		return err
	}
	t := time.NewTimer(resetWait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return net.ErrClosed
	}
	return nil
}

// resetSeq starts a fresh sequence flow on the client after a port rotation: the
// new 4-tuple is a new connection to every middlebox on the path, and a real
// connection would open with a new ISN. No-op in fixed mode.
func (c *Carrier) resetSeq() {
	if c.seqMode == SeqRealistic && c.clientSeq != nil {
		c.clientSeq.reset()
	}
}

// usableSrcIP reports whether ip is a sane reply source address.
func usableSrcIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}

// firstGlobalUnicastIPv4 returns the IPv4 of the first up, non-loopback
// interface — a dial-free fallback for egress-NIC detection when a route lookup
// is unavailable (e.g. no route to the probe address on the VPS).
func firstGlobalUnicastIPv4() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && ip.IsGlobalUnicast() {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no up, non-loopback IPv4 interface found")
}

func (c *Carrier) recvLoop() {
	// Tell Close the loop has left the packet backend for good. Close waits for
	// this before tearing the backend down: on Windows, Capture sits inside
	// pcap_next_ex, and freeing the handle underneath it faults in wpcap.dll.
	defer close(c.rxDone)
	for {
		// Checked before every Capture, so a closed carrier stops entering the
		// backend even if the last call returned normally.
		select {
		case <-c.closed:
			return
		default:
		}
		raw, err := c.pio.Capture()
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
				// Transient capture error; keep going.
				continue
			}
		}
		seg, ok := parseIPv4(raw)
		if !ok || seg.synOnly || len(seg.payload) == 0 {
			continue
		}

		var addr *Addr
		if c.opts.Role == RoleClient {
			if !seg.srcIP.Equal(c.opts.VPSIP) || seg.srcPort != uint16(c.curServerPort.Load()) || seg.dstPort != uint16(c.curClientPort.Load()) {
				continue
			}
			addr = c.peer.Load()
		} else {
			// Accept any dst port in the server span; the client rotates within it.
			span := c.opts.ServerPortSpan
			if span < 1 {
				span = 1
			}
			if int(seg.dstPort) < int(c.opts.ServerPort) || int(seg.dstPort) >= int(c.opts.ServerPort)+span {
				continue
			}
			ipCopy := make(net.IP, len(seg.srcIP))
			copy(ipCopy, seg.srcIP)
			addr = &Addr{IP: ipCopy, Port: seg.srcPort}
			// Remember the exact address the client reached us at (IP + port) so we
			// reply from it. Stored before the packet reaches the transport, so a
			// later WriteTo always finds it. The port makes the server span work;
			// the IP is used as the reply source unless VPSIP overrides it.
			if usableSrcIP(seg.dstIP) {
				dstCopy := make(net.IP, len(seg.dstIP))
				copy(dstCopy, seg.dstIP)
				c.learnedSrc.Store(addr.String(), replySrc{ip: dstCopy, port: seg.dstPort})
			}
		}

		// Mirror the peer's sequence number into our ack, so the numbers we craft
		// stay consistent with the stream a middlebox is watching.
		if c.seqMode == SeqRealistic {
			c.seqFor(addr).observe(seg.seq, len(seg.payload), seg.tsVal, seg.hasTS)
			c.checkPeerSeqMode(seg.seq)
		}

		payload := make([]byte, len(seg.payload))
		copy(payload, seg.payload)
		c.bytesIn.Add(uint64(len(payload)))

		select {
		case c.rx <- rxPacket{data: payload, addr: addr}:
		case <-c.closed:
			return
		}
	}
}

// ReadFrom implements net.PacketConn.
func (c *Carrier) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rdMu.Lock()
	dl := c.readDeadline
	c.rdMu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, timeoutError{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case pk := <-c.rx:
		n := copy(p, pk.data)
		return n, pk.addr, nil
	case <-timeout:
		return 0, nil, timeoutError{}
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo implements net.PacketConn.
func (c *Carrier) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var peer *Addr // server role: which client this reply is for
	if c.opts.Role == RoleClient {
		srcIP, srcPort = c.localIP, uint16(c.curClientPort.Load())
		dstIP, dstPort = c.opts.VPSIP, uint16(c.curServerPort.Load())
	} else {
		ip, port, ok := addrFromNet(addr)
		if !ok {
			return 0, fmt.Errorf("carrier: bad destination addr %v", addr)
		}
		peer = &Addr{IP: ip, Port: port}
		key := peer.String()
		replyIP := c.opts.VPSIP        // IP override, if configured
		replyPort := c.opts.ServerPort // fallback until we've learned the client's port
		if v, found := c.learnedSrc.Load(key); found {
			ls := v.(replySrc)
			if replyIP == nil {
				replyIP = ls.ip
			}
			replyPort = ls.port // reply from the exact port the client used (server span)
		}
		if replyIP == nil {
			return 0, fmt.Errorf("carrier: no reply source for %s yet (no inbound packet seen)", key)
		}
		srcIP, srcPort = replyIP, replyPort
		dstIP, dstPort = ip, port
	}

	// Fixed mode emits exactly the header it always has: constant seq/ack, a full
	// window, no options. Realistic mode adds the sequence bookkeeping, a jittered
	// window and the timestamp option.
	spec := segmentSpec{
		srcIP: srcIP, dstIP: dstIP,
		srcPort: srcPort, dstPort: dstPort,
		seq: carrierSeq, ack: carrierAck,
		flags:   c.flags(),
		window:  maxWindow,
		payload: p,
	}
	if c.seqMode == SeqRealistic {
		seq, ack, ts := c.seqFor(peer).next(uint32(len(p)))
		spec.seq, spec.ack = seq, ack
		spec.window = randomWindow()
		spec.ts = &ts
	}
	ipPkt, err := craftSegment(spec)
	if err != nil {
		return 0, err
	}
	if err := c.inject(ipPkt); err != nil {
		return 0, err
	}
	c.bytesOut.Add(uint64(len(p)))
	return len(p), nil
}

// Stats returns cumulative carrier bytes received and sent.
func (c *Carrier) Stats() (in, out uint64) {
	return c.bytesIn.Load(), c.bytesOut.Load()
}

// LocalAddr implements net.PacketConn.
func (c *Carrier) LocalAddr() net.Addr {
	if c.opts.Role == RoleClient {
		return &Addr{IP: c.localIP, Port: uint16(c.curClientPort.Load())}
	}
	ip := c.opts.VPSIP
	if ip == nil {
		ip = net.IPv4zero
	}
	return &Addr{IP: ip, Port: c.opts.ServerPort}
}

// SetDeadline implements net.PacketConn.
func (c *Carrier) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *Carrier) SetReadDeadline(t time.Time) error {
	c.rdMu.Lock()
	c.readDeadline = t
	c.rdMu.Unlock()
	return nil
}

// SetWriteDeadline implements net.PacketConn. Writes never block, so this is a
// no-op that only reports closure.
func (c *Carrier) SetWriteDeadline(time.Time) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

// inject is the single path to the packet backend. It exists to serialise two
// things that must never overlap:
//
//   - Two injections at once. The Windows backend serialises into one shared
//     buffer, so concurrent callers would interleave and put garbage on the wire.
//     There are genuinely concurrent callers: the transport writes from its own
//     goroutines while the reconnect loop can send a reset.
//   - An injection and Close. Close tears the backend down — on Windows that is
//     pcap_close — and a send already inside the library then touches freed native
//     state. That does not panic, it takes the process down, which is what a
//     Disconnect during a reconnect attempt was doing.
//
// After Close, injection is refused rather than attempted.
func (c *Carrier) inject(pkt []byte) error {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	return c.pio.Inject(pkt)
}

// rxDrainTimeout bounds how long Close waits for the receive loop to come out of
// the packet backend. Both backends return from a capture promptly — Npcap has a
// 10 ms read timeout, the Linux socket a receive timeout — so the wait is normally
// microseconds. The bound only stops a wedged backend from hanging shutdown.
const rxDrainTimeout = time.Second

// Close implements net.PacketConn.
//
// Order matters here, and getting it wrong is fatal rather than untidy. The
// backend must not be torn down while another goroutine is inside it:
//
//   - the receive loop blocks in pcap_next_ex (Windows) / recvfrom (Linux), and
//     freeing the pcap handle underneath it faults inside wpcap.dll — an
//     0xc0000005 that kills the process with no Go panic;
//   - an injection may be in flight for the same reason.
//
// So: signal, wait for the reader to leave, exclude injectors, and only then
// close.
func (c *Carrier) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed) // stop new injections and new captures

		// Wait for recvLoop to return. rxDone is nil only for a Carrier built
		// without Open (tests that never start the loop).
		if c.rxDone != nil {
			select {
			case <-c.rxDone:
			case <-time.After(rxDrainTimeout):
			}
		}

		// And for an injection already in progress; see inject.
		c.ioMu.Lock()
		err = c.pio.Close()
		c.ioMu.Unlock()
	})
	return err
}

// timeoutError satisfies net.Error with Timeout()==true so KCP/QUIC treat
// ReadFrom deadline expiries correctly.
type timeoutError struct{}

func (timeoutError) Error() string   { return "carrier: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
