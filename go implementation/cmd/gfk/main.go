// Command gfk is the client/server for the GFW-Knocker TCP-violation tunnel.
// It reads a YAML config (mode selects client or server), optionally installs
// firewall RST-suppression rules, brings up the fake-TCP carrier, and runs the
// selected role.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/carrier"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/firewall"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/logx"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/supervisor"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/tunnel"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/version"
)

func main() {
	cfgPath := flag.String("config", "", "path to YAML config file")
	dropRST := flag.Bool("dropRST", false, "apply firewall RST-suppression rules without prompting")
	dropRSTlc := flag.Bool("droprst", false, "alias for -dropRST")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	// Answered before anything else, so it works with no config present.
	if *showVersion {
		fmt.Println(version.Banner())
		return
	}

	if *cfgPath == "" {
		*cfgPath = defaultConfigPath() // look for a config next to the binary
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, version.Banner())
		fmt.Fprintln(os.Stderr, "usage: gfk -config <file.yaml> [-dropRST] [-version]")
		fmt.Fprintln(os.Stderr, "  (or place server.yaml / client.yaml next to the gfk binary)")
		os.Exit(2)
	}
	forceFirewall := *dropRST || *dropRSTlc

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	// Validate() already rejected an unknown level, so this cannot fail here.
	level, _ := logx.ParseLevel(cfg.LogLevel)
	logx.SetLevel(level) // also sets how much of a peer address may be logged
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	if level >= logx.LevelNone {
		handler = slog.DiscardHandler // log_level: none — emit nothing at all
	}
	logger := slog.New(handler)

	// The banner goes straight to stderr rather than through the logger: it is the
	// program identifying itself, not a log record, and slog would prefix every
	// line with a timestamp and level. It is suppressed at log_level: none — on a
	// VPS that output is usually captured by journald, and an operator who asked
	// for silence should not find the dedication line persisted in a system log.
	if level < logx.LevelNone {
		fmt.Fprintln(os.Stderr, version.Banner())
	}

	logger.Info("config loaded", "path", *cfgPath)
	logger.Info("settings in effect", cfg.EffectiveAttrs()...)

	// vps_ip is required on the client; optional on the server (auto-derived).
	var vpsIP net.IP
	if cfg.Carrier.VPSIP != "" {
		if vpsIP = net.ParseIP(cfg.Carrier.VPSIP); vpsIP == nil {
			logger.Error("carrier.vps_ip is set but not a valid IP", "value", cfg.Carrier.VPSIP)
			os.Exit(1)
		}
	}
	if cfg.Mode == config.ModeClient && vpsIP == nil {
		logger.Error("carrier.vps_ip is required for client mode")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Firewall (RST suppression) --- covers the client's port-rotation range.
	sspan := cfg.Carrier.ServerPortSpan
	if sspan < 1 {
		sspan = 1
	}
	fwRules := firewall.Rules{PortStart: cfg.Carrier.ServerPort, PortEnd: cfg.Carrier.ServerPort + uint16(sspan) - 1}
	if cfg.Mode == config.ModeClient {
		span := cfg.Carrier.ClientPortSpan
		if span < 1 {
			span = 1
		}
		fwRules = firewall.Rules{PortStart: cfg.Carrier.ClientPort, PortEnd: cfg.Carrier.ClientPort + uint16(span) - 1}
	}
	portDesc := fmt.Sprintf("%d-%d", fwRules.PortStart, fwRules.PortEnd)
	if decideFirewall(cfg.Firewall.Manage, forceFirewall) {
		remove, err := firewall.Install(fwRules)
		if err != nil {
			logger.Error("failed to apply firewall rules", "err", err)
			logger.Error("without RST suppression the OS will reset the carrier; aborting")
			os.Exit(1)
		}
		logger.Info("firewall RST-suppression rules applied", "ports", portDesc)
		defer func() {
			if err := remove(); err != nil {
				logger.Warn("failed to remove firewall rules", "err", err)
			} else {
				logger.Info("firewall rules removed")
			}
		}()
	} else {
		logger.Warn("firewall rules NOT managed by gfk; ensure kernel RSTs are suppressed on the carrier port(s) yourself", "ports", portDesc)
	}

	// --- Carrier ---
	role := carrier.RoleServer
	if cfg.Mode == config.ModeClient {
		role = carrier.RoleClient
	}
	car, err := carrier.Open(carrier.Options{
		Role:                      role,
		VPSIP:                     vpsIP,
		ServerPort:                cfg.Carrier.ServerPort,
		ClientPort:                cfg.Carrier.ClientPort,
		ClientPortSpan:            cfg.Carrier.ClientPortSpan,
		ServerPortSpan:            cfg.Carrier.ServerPortSpan,
		Interface:                 cfg.Carrier.Interface,
		TCPFlags:                  cfg.Carrier.TCPFlags,
		SeqMode:                   cfg.Carrier.SeqMode,
		Warn:                      logger.Warn,
		ResetAndWaitBeforeConnect: cfg.ResetAndWaitBeforeConnect(),
	})
	if err != nil {
		logger.Error("failed to open carrier", "err", err)
		os.Exit(1)
	}
	defer car.Close()
	// The flags/seq mode are already in the "settings in effect" line above; what
	// is new here is the NIC gfk actually resolved.
	logger.Info("carrier bound", logx.Addr("local_ip", car.LocalIP()), "interface", cfg.Carrier.Interface)

	// Not cfg.KCP: seq_mode realistic cannot keep more than one unscaled TCP window
	// in flight without a middlebox dropping the excess permanently, so the send
	// window is clamped to fit. See config.EffectiveKCP.
	kcpCfg, clamped := cfg.EffectiveKCP()
	if clamped {
		logger.Warn("kcp send window reduced to fit the carrier's window ceiling",
			"sndwnd", kcpCfg.SndWnd, "configured", cfg.KCP.SndWnd, "seq_mode", cfg.Carrier.SeqMode,
			"why", "an advancing seq cannot exceed 64 KB in flight without a SYN to negotiate window scaling; "+
				"use seq_mode: random for the same camouflage at full speed")
	}
	params := transport.Params{
		Transport: cfg.Transport,
		Key:       cfg.Auth.Key,
		// Not cfg.Carrier.MTU: the camouflaged modes spend 12 header bytes on the
		// timestamp option, and the IP packet must stay the same size either way.
		MTU:              cfg.TransportMTU(),
		KeepAliveSeconds: cfg.Client.KeepAliveSeconds,
		KCP:              kcpCfg,
		QUIC:             cfg.QUIC,
	}

	switch cfg.Mode {
	case config.ModeClient:
		runClient(ctx, cfg, car, params, logger)
	case config.ModeServer:
		runServer(ctx, cfg, car, params, logger)
	}

	logger.Info("shutdown complete")
}

func runClient(ctx context.Context, cfg config.Config, car *carrier.Carrier, params transport.Params, logger *slog.Logger) {
	delay := time.Duration(cfg.Client.ReconnectSeconds) * time.Second
	if delay <= 0 {
		delay = 3 * time.Second
	}
	dialCount := 0
	sessionWasUp := false
	// release resets the carrier tuple we are done with, so the middlebox starts
	// expiring its entry now rather than when we next need the port. Never before
	// using a tuple: see carrier.SendReset.
	release := func(why string) {
		if err := car.SendReset(); err != nil {
			logger.Debug("could not reset the carrier tuple", "when", why, "err", err)
		}
	}
	sup := supervisor.New(func(dctx context.Context) (transport.Session, error) {
		if dialCount > 0 {
			if sessionWasUp {
				// The previous session died on this tuple. Reset it before rotating
				// away, while the ports still point at it.
				release("session lost")
				sessionWasUp = false
			}
			// Reconnect: rotate the client source port (fresh flow, avoids
			// colliding with the server's still-expiring session) AND the server
			// destination port (escapes a middlebox blocking the current one).
			cp := car.RotateClientPort()
			sp := car.RotateServerPort()
			logger.Debug("rotated carrier ports for reconnect", "client_port", cp, "server_port", sp)
		}
		dialCount++
		// Opt-in recovery for a tuple poisoned by a run that never released it.
		// Costs 12s per attempt, hence off by default.
		if err := car.ResetAndWait(dctx); err != nil {
			return nil, err
		}
		// Read after rotation: this is the port actually being dialled, not the base
		// from the config. It must also be what ReadFrom reports, or the transport
		// discards every reply as coming from the wrong source.
		remote := car.RemoteAddr()
		sess, err := transport.Dial(dctx, car, remote, params)
		if err != nil {
			release("connect failed") // this port did not come up; free it, then try the next
			return nil, err
		}
		if err := tunnel.Verify(sess, cfg.Auth.Key); err != nil {
			_ = sess.Close()
			release("verify failed")
			return nil, err
		}
		sessionWasUp = true
		logger.Info(string(cfg.Transport)+" tunnel established to server", logx.Peer(remote))
		return sess, nil
	}, delay, logger)
	// Abandon a tuple a middlebox has started black-holing after ~3s, rather than
	// waiting ~16s for the transport keepalive to time out. The reconnect rotates
	// ports, which is the only thing that helps.
	sup.SetHealthCheck(car.Wedged)
	go sup.Run(ctx)

	logger.Info("client starting", "transport", cfg.Transport, logx.Addr("vps", cfg.Carrier.VPSIP))
	cl := tunnel.NewClient(cfg.Client, cfg.Auth.Key, sup, logger)
	_ = cl.Run(ctx)

	// Graceful shutdown: hand the tuple back. Without this the middlebox holds its
	// entry for days and the next run finds that port dead — the whole reason the
	// reset exists. Runs before the deferred car.Close in main, so the carrier is
	// still able to inject.
	release("shutdown")
}

func runServer(ctx context.Context, cfg config.Config, car *carrier.Carrier, params transport.Params, logger *slog.Logger) {
	lis, err := transport.Listen(car, params)
	if err != nil {
		logger.Error("failed to start transport listener", "err", err)
		os.Exit(1)
	}
	logger.Info("server starting", "transport", cfg.Transport, "backend", cfg.Server.BackendIP, "allow_socks5", cfg.Server.AllowSocks5)
	srv := tunnel.NewServer(cfg.Server, cfg.Auth.Key, logger)
	if err := srv.Serve(ctx, lis); err != nil {
		logger.Error("server stopped", "err", err)
	}
}

// decideFirewall resolves the effective firewall policy.
func decideFirewall(policy config.FirewallPolicy, forceYes bool) bool {
	if forceYes {
		return true
	}
	switch policy {
	case config.FirewallYes:
		return true
	case config.FirewallNo:
		return false
	case config.FirewallAsk:
		return promptYesNo("Apply firewall rules to suppress kernel RSTs on the carrier port? [Y/n]: ")
	}
	return false
}

func promptYesNo(prompt string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive (e.g. systemd): default to not touching the firewall.
		fmt.Fprintln(os.Stderr, "firewall.manage=ask but no terminal; skipping firewall changes (set manage: yes or pass -yes)")
		return false
	}
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "" || line == "y" || line == "yes"
}

// defaultConfigPath returns a config file sitting next to the executable when
// -config is omitted, so a gfk binary placed alongside server.yaml (e.g. in
// /root/gfk) runs with no flags.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, name := range []string{"server.yaml", "client.yaml", "gfk.yaml"} {
		p := filepath.Join(dir, name)
		if fi, statErr := os.Stat(p); statErr == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}
