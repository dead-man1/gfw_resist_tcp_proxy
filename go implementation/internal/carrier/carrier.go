package carrier

import (
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
	peer    *Addr // client mode: the single server peer

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

	rx        chan rxPacket
	closed    chan struct{}
	closeOnce sync.Once

	rdMu         sync.Mutex
	readDeadline time.Time
}

// seqState is the fake-TCP sequence bookkeeping for one flow in
// seq_mode: realistic. It makes a capture of the carrier look like an
// established connection: a random ISN, seq advancing by exactly the bytes
// sent, and an ack that tracks what the peer sent.
//
// Overflow: a real stack lets seq wrap modulo 2^32 and both ends follow the
// wrap. We cannot rely on that here — the peer ignores seq entirely, so nothing
// re-synchronises after a wrap — and 4 GB of tunnel traffic reaches it in an
// afternoon. Instead, when the next segment would carry seq past 2^32 we
// restart the flow at its ISN. To the peer this is invisible (it never looks);
// to a middlebox it looks like the flow it was tracking rolled over, which is
// the same class of event as the reconnect it already tolerates.
type seqState struct {
	mu  sync.Mutex
	isn uint32 // where this flow started, and where it restarts on overflow
	seq uint32 // sequence number for the next byte we send
	ack uint32 // what we ack: the peer's last seq + its payload length
	// seen is false until the peer's real sequence position is known. Until then
	// ack holds a plausible guess (see reset); the first inbound packet replaces
	// it outright, and from then on the ack only ever moves forward.
	seen bool
}

func newSeqState() *seqState {
	s := &seqState{}
	s.reset()
	return s
}

// reset restarts the flow with a fresh ISN. Called when the carrier 4-tuple
// changes (port rotation on reconnect), because a new tuple is a new connection
// as far as anything on the path is concerned.
//
// The ack starts at its own random value rather than at 1. We cannot know where
// the peer's sequence space really is until it sends something (there is no
// SYN-ACK to learn it from), and an ack of 1 on an otherwise mid-stream segment
// is exactly the tell realistic mode exists to remove. The guess is only ever on
// the wire until the peer's first packet arrives — one RTT — after which every
// ack we send is the truth.
func (s *seqState) reset() {
	isn, ack := randomISN(), randomISN()
	s.mu.Lock()
	s.isn, s.seq, s.ack, s.seen = isn, isn, ack, false
	s.mu.Unlock()
}

// next reserves n bytes of sequence space and returns the seq/ack pair for the
// segment carrying them.
func (s *seqState) next(n uint32) (seq, ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seq+n < s.seq { // would carry us past 2^32: restart at the ISN
		s.seq = s.isn
	}
	seq, ack = s.seq, s.ack
	s.seq += n
	return seq, ack
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
func (s *seqState) observe(peerSeq uint32, payloadLen int) {
	ack := peerSeq + uint32(payloadLen)
	if ack == 0 {
		ack = 1 // ack 0 does not occur in an established stream
	}
	s.mu.Lock()
	if !s.seen || int32(ack-s.ack) > 0 {
		s.ack, s.seen = ack, true
	}
	s.mu.Unlock()
}

// randomISN picks an initial sequence number. RFC 6528 wants these
// unpredictable; math/rand/v2 is seeded from the OS and is plenty, since nothing
// security-relevant rests on it (the payload is encrypted by the transport).
func randomISN() uint32 {
	// Stay in the low half: room to climb before a wrap. Never 0 — a real stream
	// does not sit at sequence 0, and it is the one value that would look planted.
	return 1 + rand.Uint32N(1<<31)
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
	}
	c.curClientPort.Store(uint32(opts.ClientPort))
	c.curServerPort.Store(uint32(opts.ServerPort))
	if opts.Role == RoleClient {
		c.peer = &Addr{IP: opts.VPSIP, Port: opts.ServerPort}
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
	c.resetSeq()
	return uint16(next)
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
	for {
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
			addr = c.peer
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
			c.seqFor(addr).observe(seg.seq, len(seg.payload))
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

	seq, ack := uint32(carrierSeq), uint32(carrierAck)
	if c.seqMode == SeqRealistic {
		seq, ack = c.seqFor(peer).next(uint32(len(p)))
	}
	ipPkt, err := craftSegment(srcIP, dstIP, srcPort, dstPort, seq, ack, c.flags(), p)
	if err != nil {
		return 0, err
	}
	if err := c.pio.Inject(ipPkt); err != nil {
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

// Close implements net.PacketConn.
func (c *Carrier) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.pio.Close()
	})
	return err
}

// timeoutError satisfies net.Error with Timeout()==true so KCP/QUIC treat
// ReadFrom deadline expiries correctly.
type timeoutError struct{}

func (timeoutError) Error() string   { return "carrier: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
