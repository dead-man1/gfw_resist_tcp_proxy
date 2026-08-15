//go:build linux

package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// install adds iptables rules:
//   - raw/PREROUTING + raw/OUTPUT NOTRACK for the carrier port, so conntrack
//     does not create phantom state for our handshake-less flow;
//   - mangle/OUTPUT accept of gfk's OWN reset (identified by Fwmark), which must
//     come before the drop below or SendReset's packet never leaves the host;
//   - mangle/OUTPUT drop of any other RST from the carrier port, i.e. the
//     kernel-generated ones this whole package exists to suppress.
func install(r Rules) (func() error, error) {
	start, end := r.ports()
	port := strconv.Itoa(int(start))
	if end != start {
		port = fmt.Sprintf("%d:%d", start, end) // iptables inclusive port range
	}
	mark := fmt.Sprintf("0x%x", Fwmark)
	// Each entry: table, then the rule spec (without -A/-D). Order matters for the
	// two mangle rules: they are appended in sequence, so the accept is evaluated
	// first and only unmarked (kernel) resets reach the drop.
	//
	// The accept is optional: it depends on the xt_mark match, which is standard but
	// can be absent from a stripped kernel or container. Losing it costs only
	// SendReset's reset — carrying on without it is far better than refusing to
	// start, which is what a mandatory rule would do here.
	specs := []struct {
		spec     []string
		optional bool
	}{
		{spec: []string{"raw", "PREROUTING", "-p", "tcp", "--dport", port, "-j", "NOTRACK"}},
		{spec: []string{"raw", "OUTPUT", "-p", "tcp", "--sport", port, "-j", "NOTRACK"}},
		{spec: []string{"mangle", "OUTPUT", "-p", "tcp", "--sport", port, "--tcp-flags", "RST", "RST", "-m", "mark", "--mark", mark, "-j", "ACCEPT"}, optional: true},
		{spec: []string{"mangle", "OUTPUT", "-p", "tcp", "--sport", port, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
	}

	var added [][]string
	remove := func() error {
		var errs []string
		// Remove in reverse order.
		for i := len(added) - 1; i >= 0; i-- {
			s := added[i]
			args := append([]string{"-t", s[0], "-D", s[1]}, s[2:]...)
			if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Sprintf("iptables -D %v: %v (%s)", s, err, strings.TrimSpace(string(out))))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("firewall cleanup: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	for _, s := range specs {
		args := append([]string{"-t", s.spec[0], "-A", s.spec[1]}, s.spec[2:]...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			if s.optional {
				continue // see the specs comment: not worth failing startup over
			}
			_ = remove()
			return nil, fmt.Errorf("iptables -A %v: %w (%s)", s.spec, err, strings.TrimSpace(string(out)))
		}
		added = append(added, s.spec)
	}
	return remove, nil
}
