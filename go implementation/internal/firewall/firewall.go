// Package firewall installs and removes the OS rules that stop the kernel from
// resetting the fake-TCP carrier. Because gfk fabricates TCP packets that the
// kernel has no socket for, the OS would otherwise reply with RST and also let
// conntrack interfere. On Linux we NOTRACK the carrier port(s) and drop kernel
// RSTs; on Windows we block the stack from seeing them (Npcap still captures
// below the firewall).
package firewall

// Fwmark is the netfilter mark gfk sets on its own outbound carrier packets.
//
// It exists to resolve a conflict: the Linux rules drop every outbound RST from
// the carrier ports (that is the whole point — the kernel would otherwise reset
// our socket-less flow), but gfk itself needs to send one deliberate RST to clear
// stale middlebox state when it releases a carrier tuple (Carrier.SendReset). The two
// are indistinguishable by header alone, so the sender marks its packets and the
// drop rule is preceded by an accept for that mark.
//
// Linux only; ignored on other platforms. The value is arbitrary — "gf" in
// ASCII — chosen to be unlikely to collide with an existing policy-routing rule.
const Fwmark = 0x6766

// Rules describes the carrier TCP port range to protect from the kernel.
type Rules struct {
	// PortStart..PortEnd (inclusive) is the carrier port range this side owns:
	// a single port on the server (server_port), or the client_port rotation
	// range on the client. Kernel RSTs originate from these ports; we suppress
	// them and NOTRACK the range. If PortEnd < PortStart it means a single port.
	PortStart uint16
	PortEnd   uint16
}

// ports returns the normalized inclusive [start, end] range.
func (r Rules) ports() (start, end uint16) {
	end = r.PortEnd
	if end < r.PortStart {
		end = r.PortStart
	}
	return r.PortStart, end
}

// Install applies the rules and returns a function that removes them. The
// implementation is platform-specific; on unsupported platforms it is a no-op.
func Install(r Rules) (remove func() error, err error) {
	return install(r)
}
