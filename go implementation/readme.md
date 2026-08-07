# Quick setup
1. install on linux vps ( if you dont like install script, you can manually run binary on vps in tmux)

```sh
bash <(curl -fsSL 'https://raw.githubusercontent.com/GFW-knocker/gfw_resist_tcp_proxy/main/go%20implementation/scripts/gfk.sh') install
```
2. edit client.yaml
```
vps_ip
server_port
client_port
auth_key
forwards
- {proto: tcp, listen: "0.0.0.0:12000", target_port: 443} --> this listen on pc_ip:12000 , forward traffic to vps_ip:443
```
3. edit server.yaml
```
server_port
auth_key
allowed_ports (when leave empty , client can forward its traffic to any port)
```
4. run both client and server and wait to see 
```
kcp tunnel established
```

# gfk tunnel — Go implementation

A Go rewrite of the original Python variant (in `../python implementation/`).
Same idea, but with a proper reliability layer, multiplexing, keepalive/auto-reconnect,
multi-client support, and no Python/scapy in the hot path.

## Architecture

```
tunnel/      port-forward + SOCKS5 listeners (client) · dial backend/target (server)
   │           each stream starts with an HMAC-authenticated connect header
transport/   pluggable reliability + mux:  KCP+smux(+FEC)  |  QUIC
   │           both run over a net.PacketConn
carrier/     fake-TCP net.PacketConn: craft/sniff TCP ACK+PSH, NO SYN
   │           Linux: AF_INET raw send + AF_PACKET capture (cgo-free)
   │           Windows: Npcap via wpcap.dll syscall bindings (cgo-free)
firewall/    RST suppression (iptables on Linux, Windows Firewall on Windows)
```

The carrier is **connectionless**: it never "disconnects", so reconnection only
re-establishes the KCP/QUIC session on top (handled by `supervisor/`). Because the
carrier's `ReadFrom` reports each packet's real source address, one server
demultiplexes many client PCs automatically.

## Build

The **CLI** (`cmd/gfk`, client + server) is cgo-free:

```sh
# Linux server / Linux client:
CGO_ENABLED=0 GOOS=linux  go build -o gfk      ./cmd/gfk
# Windows client (needs Npcap runtime installed on the target machine):
CGO_ENABLED=0 GOOS=windows go build -o gfk.exe ./cmd/gfk
```

The **Windows GUI** (`cmd/gfk-gui`, Fyne) is built separately behind the `gui`
build tag and needs cgo + a C compiler (mingw-w64):

```sh
CGO_ENABLED=1 go build -tags gui -o gfk-windows-GUI.exe ./cmd/gfk-gui
```

> Caveat: `go mod tidy` run *without* `-tags gui` will prune Fyne from `go.mod`
> (it's only imported under that tag). If that happens, `go get fyne.io/fyne/v2`
> to restore it. The `gui` tag keeps Fyne entirely out of the cgo-free CLI build.

## Version and banner

Both front-ends print an identity banner at startup — the CLI to stderr, the GUI at
the top of its log pane:

```
====================================================
                  gfk tunnel v2.0
https://github.com/GFW-knocker/gfw_resist_tcp_proxy/
              in memory of Mahsa-Amini
====================================================
```

Everything in it lives in [`internal/version/version.go`](internal/version/version.go)
and nowhere else. **To cut a release, change `Version` there and stop** — the banner
measures its own rules and re-centres its lines, so the box stays square whatever
the strings become (including a non-ASCII dedication; it counts runes, not bytes).
`gfk -version` prints the banner and exits.

Two deliberate details: the CLI banner is **suppressed at `log_level: none`**,
because on a VPS stderr usually lands in journald and an operator who asked for
silence should not find the dedication line persisted in a system log; the GUI
banner always shows, since that pane lives and dies with the window. Clearing the
GUI log re-prints it, so a copied log always says which version produced it.

## Releasing (CI)

`.github/workflows/release.yml` builds everything and publishes a GitHub Release.
Trigger it from the **Actions** tab → **Release** → **Run workflow**, entering the
**tag** (e.g. `v0.1.0`, created if new) and **title**. It produces:

- CLI (cgo-free, cross-compiled on one Linux runner): `gfk-linux-{amd64,arm64,armv7,386}`,
  `gfk-windows-{amd64,arm64}.exe`.
- Windows GUI (native cgo build on a Windows runner): `gfk-windows-GUI.exe`.
- Config templates: `server.yaml`, `client.yaml` (copied from `config/*.example.yaml`).

The `gfk.sh` installer pulls `gfk-linux-amd64` / `gfk-linux-arm64` from that release.

> macOS is not built: the raw-packet carrier is linux/windows only. The code still
> compiles on darwin (via `internal/carrier/packetio_other.go`, which fails cleanly
> at startup) — a functional macOS client would need a BPF/libpcap backend.

## Run

Edit `config/server.example.yaml` / `config/client.example.yaml` (set `vps_ip`,
a shared `auth.key`, ports, forwards). Then:

> `vps_ip` is required on the **client** (where to send / whose replies to accept)
> but **optional on the server** — leave it empty and the server derives each
> client's reply source IP from inbound packets. That's the recommended default
> and is also what makes it work behind 1:1-NAT clouds (AWS/GCP/Oracle), where a
> forced public source IP gets dropped by egress anti-spoofing.

```sh
# server (VPS, root):
sudo ./gfk -config server.yaml            # -dropRST to apply firewall rules unprompted

# client (PC, admin + Npcap on Windows / root on Linux):
./gfk -config client.yaml
```

If `-config` is omitted, gfk looks for `server.yaml` / `client.yaml` next to the
binary — so a `gfk` binary sitting alongside its config (e.g. `/root/gfk/`) runs
with no flags.

**Easiest server setup** — the `gfk` installer (`scripts/gfk.sh`, kept in the repo)
downloads the right binary from the GitHub release into `/root/gfk/` (next to its
config), installs a boot-enabled systemd service, and gives you
`gfk {start|stop|restart|status|log|edit|update|uninstall}`:

```sh
bash <(curl -fsSL 'https://raw.githubusercontent.com/GFW-knocker/gfw_resist_tcp_proxy/main/go%20implementation/scripts/gfk.sh') install
```

Publish a GitHub release with just the two binaries `gfk-linux-amd64` and
`gfk-linux-arm64` (built in `dist/`); the installer script is served from the repo,
not the release.

Both sides need to suppress kernel RSTs on the carrier port. gfk does this itself
(prompts once, unless `firewall.manage: yes` or `-dropRST`).

### Forwarding several ports at once (client)

`client.forwards` is a list — each entry is an independent local listener mapped
to a server-side `target_port`, and they **all run simultaneously over the single
tunnel** (one KCP session, smux-multiplexed; not one tunnel per port). Each
`listen` must be unique; targets may differ:

```yaml
client:
  forwards:
    - {proto: tcp, listen: "127.0.0.1:14000", target_port: 2096}
    - {proto: tcp, listen: "127.0.0.1:15000", target_port: 443}
    - {proto: tcp, listen: "127.0.0.1:16000", target_port: 2083}
    - {proto: udp, listen: "127.0.0.1:17000", target_port: 945}
```

A connection to `127.0.0.1:15000` reaches `backend_ip:443` on the server, one to
`:16000` reaches `:2083`, and so on. This works alongside `socks5_listen` (a
SOCKS5 proxy over the same tunnel).

### Surviving a blocked carrier port (port spans)

If a middlebox starts dropping a specific carrier port, gfk recovers on reconnect
without any manual change:

- `carrier.client_port_span` — the client rotates its **source** port each
  reconnect (avoids colliding with the server's still-expiring old session).
- `carrier.server_port_span` — the **server accepts a whole range** of ports, and
  the client rotates the **destination** port it targets each reconnect, stepping
  past a blocked one (a blocked port just costs one ~8 s hello-verify timeout).
  **Must match on both ends** (like the PSK). Default 8.

Rotation (server can't signal a new port over a dead tunnel) is avoided in favour
of a span: the server passively listens on the whole range, so no coordination is
needed. The RST-suppression firewall auto-covers each side's full range.

The two spans are **independent**, which is easy to misread in a packet capture:
with `client_port_span: 2` and `server_port_span: 8` the client's *source* port
only ever alternates between 40000 and 40001, while its *destination* port sweeps
45000–45007. Eight ports on the wire, and `client_port_span` is still being
honoured — it is the destination side you are watching.

### Shaping the fake TCP packets (`tcp_flags`, `seq_mode`)

Carrier packets are hand-crafted, so their TCP header is a policy choice:

```yaml
carrier:
  tcp_flags: [ack, psh]   # any of ack, psh (push), urg, fin
  seq_mode: fixed         # fixed | realistic
```

- `carrier.tcp_flags` — control bits on every crafted segment. Default
  `[ack, psh]`, what a real mid-stream data segment carries. `syn` and `rst` are
  **refused by config validation**: a SYN is the one packet the GFW matches
  against its IP blocklist (sending one defeats the whole design), and a RST
  tells every middlebox on the path to drop the flow. `psh`/`urg` are only set on
  segments that actually carry payload, and `urg` also gets an urgent pointer, so
  the header stays a combination a real stack could emit.
- `carrier.seq_mode` — `fixed` (default) pins seq and ack to 1 on every packet.
  That is maximally safe for window-tracking NAT, but a capture makes the tunnel
  obvious. `realistic` makes **both** numbers behave like an established
  connection:
  - **seq** starts at a random ISN and advances by exactly the bytes sent. On
    reaching the 32-bit limit the flow restarts at its ISN rather than wrapping
    (the peer never reads seq, so the restart is invisible to it).
  - **ack** starts at its own random, plausible position — there is no SYN-ACK to
    learn the peer's real ISN from, and an ack of `1` would be the same giveaway
    as a seq of `1`. The first packet from the peer replaces the guess with the
    truth, and from then on the ack only ever moves forward, exactly like a real
    cumulative ack (a reordered or retransmitted segment cannot pull it back).
  - **window** jitters within `[64800, 65535]` instead of being the same value on
    every packet. The band is deliberately narrow: this field is also what a
    stateful middlebox uses as the ceiling for the *peer's* sequence numbers
    (conntrack's `td_maxend = our_ack + our_window`), and with no SYN there is no
    window scale to negotiate, so 65535 is a hard maximum and every byte shaved
    off is a byte less of the peer's data allowed in flight. ~1% jitter breaks the
    constant-value signature without trading away robustness.
  - **RFC 7323 timestamps** are added — `NOP, NOP, TS` (12 bytes), byte for byte
    the option block Linux and Windows put on established-connection segments. A
    bare 20-byte header mid-stream is itself a signature. TSval is a per-flow
    random base over a 1 ms clock (as Linux offsets each connection); TSecr echoes
    the peer's clock, following the same guess-then-truth-then-forward-only rule as
    the ack. A peer that sends no timestamps is tolerated.
  - Port rotation starts a fresh ISN, a fresh ack guess and a fresh timestamp base,
    since the new 4-tuple is a new connection to everything on the path.
  - The 12 option bytes come **out of the payload budget**, not on top of it, so
    the IP packet is `mtu + 40` in both modes and switching cannot push a
    path-MTU-limited link over the edge. The startup log shows both figures
    (`mtu=1400 transport_mtu=1388`).

  A dump of a live `realistic` flow (client side), before and after the server
  first speaks:

      seq=713228218 ack=871834161  win=65244 tsval=751858357 tsecr=417278681 len=5
      seq=713228223 ack=871834161  win=65009 tsval=751858357 tsecr=417278681 len=14
      ... server sends 40 bytes at seq 3221225472, tsval 918273645 ...
      seq=713228237 ack=3221225512 win=64847 tsval=751858357 tsecr=918273645 len=1
      seq=713228238 ack=3221225512 win=65193 tsval=751858357 tsecr=918273645 len=1  <- late packet: no regression
      seq=713228239 ack=3221225522 win=65460 tsval=751858370 tsecr=918273657 len=1  <- both advance

  versus the same exchange in `fixed` mode:

      seq=1 ack=1 win=65535 (no options) len=5
      seq=1 ack=1 win=65535 (no options) len=14

  What `realistic` still does **not** disguise: the absent SYN handshake (by
  design — it is the whole point), and the absence of SACK blocks, which a real
  loss-affected stream would occasionally carry. It also cannot fake a plausible
  *response* to loss, since KCP/QUIC above us own retransmission. A DPI comparing
  against a genuine stack can still tell.

`tcp_flags` genuinely does not have to match: each side crafts its own packets and
the receiver accepts any flags but SYN.

**`seq_mode` DOES have to match** — this is the one that bites. gfk ignores the
peer's numbers, but a stateful NAT does not. It validates your climbing seq
against *the peer's last ack plus the peer's window*; a `fixed` peer acks `1`
forever, so that ceiling never rises, and one window later (65535 bytes — about
24 s on a slow link, which is exactly the failure this project already hit) every
packet you send is out-of-window and dropped. Realistic mode is safe **only**
because a realistic peer's ack advances to cover what you sent. So:

| client | server | result |
|---|---|---|
| `fixed` | `fixed` | safest, and the default. Obvious in a capture. |
| `realistic` | `realistic` | looks like a real stream, and the acks keep each other in-window. |
| `realistic` | `fixed` (either way round) | **broken** — dies one 64 KB window in. |

gfk detects the broken pairing at runtime: after three inbound packets stuck at
`seq=1` it logs

    peer looks like seq_mode: fixed while this side is realistic — set seq_mode
    the same on both ends, or a stateful NAT will drop this direction about one
    64 KB window from now

If a matched `realistic` pair still dies after ~24 s, some box on the path is
unhappy in a way we have not modelled: fall back to `fixed`.

### How packets are captured (and what it costs)

There is **no kernel-level filter**. Linux binds `AF_PACKET`/`SOCK_DGRAM` with
`ETH_P_IP` to the NIC, Windows opens Npcap in promiscuous mode with no BPF
program, so *every* IPv4 packet on the interface is copied to userspace. The
carrier then decides in Go, per packet, in this order:

1. parse as IPv4+TCP — anything else is dropped;
2. drop if **SYN** is set (not carrier data) or the payload is empty;
3. **port match** — server: destination port inside `[server_port,
   server_port+server_port_span)`; client: source IP/port must be the VPS and the
   destination port the current rotated client port.

So the port span is a userspace comparison, not a capture filter, and no TCP flag
other than SYN takes part in the decision. Measured on an i5-13420H:

| per packet | cost | allocations |
|---|---|---|
| parse + reject (not our port) | ~370 ns | 1216 B |
| parse + accept + hand to transport | ~1.1 µs | 2808 B |
| craft + serialize an outbound packet | ~1.6 µs | 5504 B |

That is ~2.7 M rejected packets/s per core, so at ordinary VPS rates the capture
is not the bottleneck: 100 Mbps of unrelated traffic (~9 k pkt/s) costs well under
1% of a core, and the accept path sustains ~875 k pkt/s (≈9 Gbps at mtu 1400).
Two caveats worth knowing:

- The cost scales with **packets per second on the whole interface**, not with
  tunnel throughput. A small-packet flood (≥500 k pkt/s) on a busy VPS will burn
  real CPU parsing packets that are then discarded.
- The allocation volume matters more than the CPU: ~1.2 KB of garbage per captured
  packet is GC pressure at high rates. Attaching a real BPF filter (the unused
  `bpfFilter` sketch in `packetio.go`) or hand-rolling the 20-byte header parse
  would remove nearly all of it. Neither is needed at current speeds.

Run the numbers yourself with `go test ./internal/carrier/ -bench . -run XXX`.

### Restricting destination ports (server)

Set `server.allowed_ports` to limit which ports clients may reach (applies to
both port-forwards and SOCKS targets). Empty = any port.

```yaml
server:
  allowed_ports: [443, 2096, 2052]   # clients can only reach these ports
```

### Throughput / latency tuning (`kcp:`)

Run with `nc: 1` (KCP's normal, no-congestion-control mode) and size the **window**
(`sndwnd`/`rcvwnd`, packets) to the link's bandwidth-delay product — this is the one
knob that matters:

    window_pkts ≈ bandwidth_bps × RTT_seconds / 8 / mtu

Too small caps throughput; too large causes bufferbloat (high jitter under load).
The smux buffers auto-size from the window (`stream_buffer`/`session_buffer: 0`), so
you normally tune only the window. Starting points:

| line speed | sndwnd / rcvwnd |
|---|---|
| dial-up ≤256 kbps | 16 |
| slow 1–6 Mbps (default) | 128 |
| broadband 10–50 Mbps | 512 |
| fast 100–500 Mbps | 8192 |

Set the same `nc` + window on **both** ends. For a lossy/adversarial link add
`fec_data: 10` / `fec_parity: 3` (must match on both ends; ~30% bandwidth cost).
Avoid `nc: 0` — kcp-go's congestion control underperforms badly over this carrier
(collapses throughput). Bound bufferbloat with the window instead.

### Logging and client privacy (`log_level`)

`log_level` takes `none | error | warn | info | debug`, and it also decides how
much of a peer address reaches the log — the server log is the one place a
client's real IP appears:

| level | what is logged | peer address |
|---|---|---|
| `none` | nothing at all | never printed |
| `error` | failures | masked |
| `warn` | failures + warnings | masked |
| `info` (default) | normal operation | masked: `peer=140.170.*.*:443` |
| `debug` | everything, incl. per-session detail | full: `peer=140.170.23.9:443` |

Masking drops the last two IPv4 octets (the last six IPv6 groups), keeping enough
to tell which network a client came from without identifying it. A hostname that
is not an IP is replaced entirely with `*`. Use `debug` only while
troubleshooting: that log identifies your users.

## Requirements

- **Linux**: root (raw sockets + iptables). No libpcap needed.
- **Windows**: Administrator + [Npcap](https://npcap.com) installed (runtime only,
  no SDK).

## Windows GUI

`gfk-windows-GUI.exe` is a single self-contained window (no runtime deps beyond Npcap):
enter VPS IP / shared key / transport / SOCKS5 / forwards (or Load a client.yaml),
tick "Manage firewall", and Connect. It shows live connection status, up/down
throughput, and a log pane. Run as Administrator.

The log pane is **selectable**: drag to select, right-click for Copy / Select all,
or Ctrl+C. The Copy button still grabs the whole log in one click. It renders in a
monospace font, which is also what makes the startup banner line up — the banner is
centred with spaces, so it only looks centred when every glyph is the same width.
Long lines are not wrapped (the pane scrolls sideways instead), so a wide
`settings in effect` line stays on one line and the banner keeps its shape on a
narrow window. The trade-off for selectable text is that Fyne's editable widget
carries a single colour for all of it, so log lines are no longer tinted by level —
each line still names its level as text (`15:04:05 WARN  msg=...`).

### The GUI honours the whole config file, not just its fields

The window deliberately exposes only the handful of settings people change often.
Everything else is still read from the YAML and applied on Connect:

| in the window | file-only (no widget) |
|---|---|
| vps_ip, shared key, transport, mtu | carrier.interface, carrier.tcp_flags, carrier.seq_mode |
| server_port + span, client_port + span | the whole `kcp:` and `quic:` blocks |
| socks5_listen, forwards, manage firewall | client.keepalive_seconds, client.reconnect_seconds, log_level |

So the normal flow works as expected: **Load** a config, change the VPS IP, hit
**Connect** — your FEC settings, window sizes, `seq_mode`, NIC override and log
level all still apply. Editing a field only overrides that field. **Save** writes
the merged result back (as plain YAML — comments in the original file are lost).

A `client.yaml` (or `gfk.yaml`) sitting next to the exe is loaded automatically at
startup, so the file-only settings are in effect even before you press Load.

To confirm what actually took effect, read the `settings in effect` line the log
pane prints on Connect — it lists every file-only value. The CLI prints the same
line at startup.
