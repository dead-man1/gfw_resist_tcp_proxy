//go:build gui

// Command gfk-gui is the Windows desktop client (Fyne). It wraps the same
// client engine as the CLI: fake-TCP carrier -> KCP/QUIC transport -> port
// forwards + SOCKS5. Built separately from the cgo-free CLI via `-tags gui`.
package main

import (
	"context"
	"fmt"
	"image/color"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"gopkg.in/yaml.v3"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/carrier"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/firewall"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/logx"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/supervisor"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/tunnel"
)

var (
	colGreen  = color.NRGBA{R: 0x2e, G: 0xcc, B: 0x71, A: 0xff}
	colAmber  = color.NRGBA{R: 0xf3, G: 0x9c, B: 0x12, A: 0xff}
	colGrey   = color.NRGBA{R: 0x95, G: 0xa5, B: 0xa6, A: 0xff}
	colRed    = color.NRGBA{R: 0xe7, G: 0x4c, B: 0x3c, A: 0xff}
	colYellow = color.NRGBA{R: 0xf1, G: 0xc4, B: 0x0f, A: 0xff}
)

// maxLogLines caps the log pane's scrollback.
const maxLogLines = 400

// screenFraction is how much of the usable screen height the window takes at
// startup, leaving the frame clear of the taskbar.
const screenFraction = 0.88

// Fixed widths for the status and rate cells flanking the Connect button. The
// rate cell holds the widest reading ("▼ 1023.9 KB/s   ▲ 1023.9 KB/s") so a
// right-aligned value never spills over the button.
const (
	statusCellWidth = 150
	rateCellWidth   = 235
)

// Down/up markers for the transfer rate. Deliberately the Geometric Shapes
// triangles, not the arrows U+2193/U+2191: Fyne resolves those two through the
// emoji font and trails a literal U+FFFD replacement glyph after each one. These
// come from the same block as the ●/○ status dots, which render clean.
const (
	glyphDown = "▼"
	glyphUp   = "▲"
)

// rateIdle is the transfer-rate text shown while nothing is flowing.
const rateIdle = glyphDown + " 0 B/s   " + glyphUp + " 0 B/s"

// localAddr / lanAddr are swapped in the listen fields by the "allow LAN" check.
const (
	localAddr = "127.0.0.1"
	lanAddr   = "0.0.0.0"
)

type ui struct {
	win fyne.Window

	cfgPath  *widget.Entry
	vps      *widget.Entry
	key      *widget.Entry
	trans    *widget.Select
	srvPort  *widget.Entry
	srvSpan  *widget.Entry
	cliPort  *widget.Entry
	cliSpan  *widget.Entry
	mtu      *widget.Entry
	socks    *widget.Entry
	forwards *widget.Entry
	firewall *widget.Check
	lan      *widget.Check
	loadBtn  *widget.Button
	saveBtn  *widget.Button

	connectBtn *widget.Button
	status     *canvas.Text
	rate       *canvas.Text
	logView    *widget.RichText
	logScroll  *container.Scroll
	autoScroll *widget.Check

	// settingsTheme dims the input backgrounds of the settings block while the
	// tunnel runs; split/naturalTop drive the startup geometry.
	settingsTheme *container.ThemeOverride
	split         *container.Split
	naturalTop    float32

	logger *slog.Logger
	logh   *uiLogHandler

	// base is the config the form was last populated from (defaults, or the file
	// loaded with Load). buildConfig starts from it, so settings with no widget
	// here — tcp_flags, seq_mode, log_level, the kcp tuning — survive a Save
	// instead of being reset to the defaults.
	base config.Config

	mu     sync.Mutex
	eng    *engine
	ticker chan struct{}
}

func main() {
	a := app.NewWithID("org.gfwknocker.gfk")
	a.Settings().SetTheme(gfkTheme{Theme: theme.DefaultTheme()})
	w := a.NewWindow("gfk — GFW Knocker")
	u := newUI(w)
	w.SetContent(u.build())
	w.Resize(fyne.NewSize(740, 720)) // fallback; applyStartSize refines it below
	u.autoLoadConfig()               // after build(): it writes to the form widgets

	if !isElevated() {
		u.logger.Warn("not running as Administrator — raw sockets, Npcap and firewall changes will fail; restart elevated")
	} else {
		u.logger.Info("gfk client ready")
	}
	w.SetCloseIntercept(func() {
		u.disconnect()
		w.Close()
	})
	// Show before Run so the canvas scale is known; ShowAndRun would deny us the
	// chance to size the window against the real screen.
	w.Show()
	u.applyStartSize()
	a.Run()
}

// applyStartSize sizes the window to a fraction of the usable screen height and
// parks the divider just below the settings, so every field is visible and the
// log takes whatever is left.
func (u *ui) applyStartSize() {
	px := usableContentHeightPx()
	if px <= 0 {
		return // unknown screen: keep the fallback size
	}
	scale := u.win.Canvas().Scale()
	if scale <= 0 {
		scale = 1
	}
	height := float32(px) * screenFraction / scale
	if height < u.naturalTop {
		height = u.naturalTop // never start smaller than the settings need
	}
	u.win.Resize(fyne.NewSize(u.win.Canvas().Size().Width, height))

	offset := float64(u.naturalTop / height)
	if offset > 0.85 {
		offset = 0.85
	}
	u.split.SetOffset(offset)
}

func newUI(w fyne.Window) *ui {
	d := config.Default()
	u := &ui{win: w, base: d}
	u.cfgPath = entry("client.yaml")
	u.vps = entry("")
	u.key = widget.NewPasswordEntry()
	u.trans = widget.NewSelect([]string{string(config.TransportKCP), string(config.TransportQUIC)}, nil)
	u.trans.SetSelected(string(d.Transport))
	u.srvPort = entry(strconv.Itoa(int(d.Carrier.ServerPort)))
	u.srvSpan = entry(strconv.Itoa(d.Carrier.ServerPortSpan))
	u.cliPort = entry(strconv.Itoa(int(d.Carrier.ClientPort)))
	u.cliSpan = entry(strconv.Itoa(d.Carrier.ClientPortSpan))
	u.mtu = entry(strconv.Itoa(d.Carrier.MTU))
	u.socks = entry(localAddr + ":1080")
	u.forwards = widget.NewMultiLineEntry()
	u.forwards.SetPlaceHolder("one per line:  tcp " + localAddr + ":14000 443")
	u.firewall = widget.NewCheck("Manage firewall RST rules (recommended)", nil)
	u.firewall.SetChecked(true)
	// Label kept short: it shares a row with the firewall check.
	u.lan = widget.NewCheck("Allow connections from LAN ("+lanAddr+")", u.onLANToggle)

	u.status = canvas.NewText("○ disconnected", colGrey)
	u.status.TextStyle = fyne.TextStyle{Bold: true}
	u.rate = canvas.NewText(rateIdle, colGrey)
	u.rate.Alignment = fyne.TextAlignTrailing // pin the reading to the window edge

	u.logView = widget.NewRichText()
	u.logView.Wrapping = fyne.TextWrapWord
	u.logScroll = container.NewVScroll(u.logView)
	u.autoScroll = widget.NewCheck("Auto-scroll", nil)
	u.autoScroll.SetChecked(true)

	u.logh = &uiLogHandler{level: slog.LevelInfo, append: u.appendLog}
	u.logger = slog.New(u.logh)
	u.applyLogLevel(d.LogLevel)
	return u
}

// applyLogLevel sets the log pane's threshold and the peer-address redaction
// policy from a config log_level value. An unusable value keeps the current
// level rather than silencing the pane.
func (u *ui) applyLogLevel(name string) {
	level, err := logx.ParseLevel(name)
	if err != nil {
		u.logger.Warn("ignoring log_level", "err", err)
		return
	}
	u.logh.level = level
	logx.SetLevel(level)
}

func (u *ui) build() fyne.CanvasObject {
	u.loadBtn = widget.NewButton("Load", u.loadConfig)
	u.saveBtn = widget.NewButton("Save", u.saveConfig)

	form := widget.NewForm(
		widget.NewFormItem("Config file", container.NewBorder(nil, nil, nil,
			container.NewHBox(u.loadBtn, u.saveBtn), u.cfgPath)),
		widget.NewFormItem("VPS IP", u.vps),
		widget.NewFormItem("Shared key", u.key),
		widget.NewFormItem("Transport", trailingField(u.trans, "MTU", u.mtu)),
		widget.NewFormItem("Server port", trailingField(u.srvPort, "+ span", u.srvSpan)),
		widget.NewFormItem("Client port", trailingField(u.cliPort, "+ span", u.cliSpan)),
		widget.NewFormItem("SOCKS5 listen", u.socks),
		widget.NewFormItem("Forwards", u.forwards),
	)

	u.connectBtn = widget.NewButton("Connect", u.toggle)
	u.connectBtn.Importance = widget.HighImportance

	// Status hugs the left edge, transfer rate the right, Connect stretches
	// between them. Fixed-width cells keep the button from twitching as the
	// readings change length; the padding is the gap either side of the button.
	statusRow := container.NewBorder(nil, nil,
		fixedCell(u.status, statusCellWidth), fixedCell(u.rate, rateCellWidth),
		container.NewPadded(u.connectBtn))

	// Settings scroll so they narrow gracefully; Connect + status stay pinned to
	// the bottom of the top pane so they are reachable however it is sized. The
	// theme override lets the whole block grey out while the tunnel runs.
	// Firewall check left, LAN check pushed out to the right edge.
	checks := container.NewHBox(u.firewall, layout.NewSpacer(), u.lan)
	settingsBox := container.NewVBox(form, checks)
	u.settingsTheme = container.NewThemeOverride(settingsBox, gfkTheme{Theme: theme.DefaultTheme()})
	settings := container.NewVScroll(u.settingsTheme)
	settings.SetMinSize(fyne.NewSize(0, 120))
	controls := container.NewVBox(widget.NewSeparator(), statusRow)
	topPane := container.NewBorder(nil, controls, nil, nil, settings)
	u.naturalTop = settingsBox.MinSize().Height + controls.MinSize().Height + 4*theme.Padding()

	logBar := container.NewHBox(
		widget.NewLabelWithStyle("Log", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		layout.NewSpacer(),
		u.autoScroll,
		widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), u.copyLog),
		widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), u.clearLog),
	)
	logPane := container.NewBorder(logBar, nil, nil, nil, u.logScroll)

	// Draggable divider: the log area is flexible and user-adjustable.
	u.split = container.NewVSplit(topPane, logPane)
	u.split.SetOffset(0.74)
	return u.split
}

// fixedCell centres a text at a fixed width, so neighbours keep their geometry
// when its content changes length.
func fixedCell(txt *canvas.Text, width float32) fyne.CanvasObject {
	sized := container.New(layout.NewGridWrapLayout(fyne.NewSize(width, txt.MinSize().Height)), txt)
	return container.NewCenter(sized)
}

// trailingField puts a second, narrow labelled field on the right of a form row
// so related settings (port + span, transport + MTU) share one line. The label is
// bold and colon-suffixed to match the form's own labels.
func trailingField(main fyne.CanvasObject, label string, trailing *widget.Entry) fyne.CanvasObject {
	name := widget.NewLabelWithStyle(label+":", fyne.TextAlignTrailing, fyne.TextStyle{Bold: true})
	sized := container.New(layout.NewGridWrapLayout(fyne.NewSize(90, trailing.MinSize().Height)), trailing)
	return container.NewBorder(nil, nil, nil, container.NewHBox(name, sized), main)
}

func (u *ui) toggle() {
	u.mu.Lock()
	running := u.eng != nil
	u.mu.Unlock()
	if running {
		u.disconnect()
	} else {
		u.connect()
	}
}

func (u *ui) connect() {
	cfg, err := u.buildConfig()
	if err != nil {
		u.logger.Error("invalid config", "err", err)
		return
	}
	u.setInputs(false)
	u.connectBtn.SetText("Disconnect")
	u.setStatus(supervisor.StateConnecting)

	go func() {
		eng, err := startEngine(cfg, u.firewall.Checked, u.setStatus, u.logger)
		if err != nil {
			u.logger.Error("failed to start", "err", err)
			fyne.Do(func() {
				u.setInputs(true)
				u.connectBtn.SetText("Connect")
				u.setStatusText("○ start failed", colRed)
			})
			return
		}
		u.mu.Lock()
		u.eng = eng
		u.ticker = make(chan struct{})
		stop := u.ticker
		u.mu.Unlock()
		go u.pollRate(eng.car, stop)
	}()
}

func (u *ui) disconnect() {
	u.mu.Lock()
	eng := u.eng
	u.eng = nil
	if u.ticker != nil {
		close(u.ticker)
		u.ticker = nil
	}
	u.mu.Unlock()
	if eng != nil {
		eng.stop()
		u.logger.Info("disconnected")
	}
	fyne.Do(func() {
		u.setInputs(true)
		u.connectBtn.SetText("Connect")
		u.setStatusText("○ disconnected", colGrey)
		u.rate.Text = rateIdle
		u.rate.Color = colGrey
		u.rate.Refresh()
	})
}

func (u *ui) pollRate(car *carrier.Carrier, stop chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	lastIn, lastOut := car.Stats()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			in, out := car.Stats()
			di, do := in-lastIn, out-lastOut
			lastIn, lastOut = in, out
			txt := fmt.Sprintf("%s %s/s   %s %s/s", glyphDown, humanBytes(di), glyphUp, humanBytes(do))
			fyne.Do(func() {
				u.rate.Text = txt
				u.rate.Color = colGreen
				u.rate.Refresh()
			})
		}
	}
}

func (u *ui) setStatus(st supervisor.State) {
	switch st {
	case supervisor.StateUp:
		u.setStatusText("● connected", colGreen)
	case supervisor.StateConnecting:
		u.setStatusText("● connecting…", colAmber)
	case supervisor.StateDown:
		u.setStatusText("● reconnecting…", colAmber)
	}
}

func (u *ui) setStatusText(s string, c color.Color) {
	fyne.Do(func() {
		u.status.Text = s
		u.status.Color = c
		u.status.Refresh()
	})
}

func (u *ui) setInputs(enabled bool) {
	widgets := []fyne.Disableable{u.vps, u.key, u.trans, u.srvPort, u.srvSpan, u.cliPort, u.cliSpan,
		u.mtu, u.socks, u.forwards, u.firewall, u.lan, u.cfgPath, u.loadBtn, u.saveBtn}
	for _, wdg := range widgets {
		if enabled {
			wdg.Enable()
		} else {
			wdg.Disable()
		}
	}
	// Grey the field backgrounds too, which Disable() alone does not do.
	u.settingsTheme.Theme = gfkTheme{Theme: theme.DefaultTheme(), dimInputs: !enabled}
	u.settingsTheme.Refresh()
}

// onLANToggle rewrites the listen addresses so the forwards and the SOCKS5
// proxy are reachable from the local network (or only from this machine).
func (u *ui) onLANToggle(on bool) {
	from, to := localAddr, lanAddr
	if !on {
		from, to = lanAddr, localAddr
	}
	for _, e := range []*widget.Entry{u.socks, u.forwards} {
		if strings.Contains(e.Text, from) {
			e.SetText(strings.ReplaceAll(e.Text, from, to))
		}
	}
}

// syncLAN aligns the checkbox with the listen addresses currently in the form
// without triggering another rewrite.
func (u *ui) syncLAN() {
	u.lan.Checked = strings.Contains(u.socks.Text, lanAddr) || strings.Contains(u.forwards.Text, lanAddr)
	u.lan.Refresh()
}

// formValues is the content of every setting this window actually exposes. The
// window has fields for a deliberately small subset of the config; everything
// else — kcp/quic tuning, interface, tcp_flags, seq_mode, the keepalive and
// reconnect timers, log_level, the whole server section — has no widget and is
// carried through from the loaded file untouched.
type formValues struct {
	transport string
	vps       string
	key       string
	srvPort   string
	srvSpan   string
	cliPort   string
	cliSpan   string
	mtu       string
	socks     string
	forwards  string
	firewall  bool
}

// overlayForm layers the window's fields onto the config the form was populated
// from. Split out from buildConfig so the passthrough guarantee — edit the VPS
// IP, keep every invisible setting — is testable without a display.
func overlayForm(base config.Config, f formValues) (config.Config, error) {
	cfg := base
	cfg.Mode = config.ModeClient
	cfg.Transport = config.Transport(f.transport)
	cfg.Carrier.VPSIP = strings.TrimSpace(f.vps)
	cfg.Carrier.ServerPort = atou16(f.srvPort, cfg.Carrier.ServerPort)
	cfg.Carrier.ClientPort = atou16(f.cliPort, cfg.Carrier.ClientPort)
	cfg.Carrier.ServerPortSpan = atoiDef(f.srvSpan, cfg.Carrier.ServerPortSpan)
	cfg.Carrier.ClientPortSpan = atoiDef(f.cliSpan, cfg.Carrier.ClientPortSpan)
	if m, err := strconv.Atoi(strings.TrimSpace(f.mtu)); err == nil {
		cfg.Carrier.MTU = m
	}
	cfg.Auth.Key = f.key
	cfg.Client.Socks5Listen = strings.TrimSpace(f.socks)
	fws, err := parseForwards(f.forwards)
	if err != nil {
		return cfg, err
	}
	cfg.Client.Forwards = fws
	if f.firewall {
		cfg.Firewall.Manage = config.FirewallYes
	} else {
		cfg.Firewall.Manage = config.FirewallNo
	}
	return cfg, cfg.Validate()
}

// buildConfig assembles and validates a client config from the form fields,
// layered over the config the form was populated from.
func (u *ui) buildConfig() (config.Config, error) {
	return overlayForm(u.base, formValues{
		transport: u.trans.Selected,
		vps:       u.vps.Text,
		key:       u.key.Text,
		srvPort:   u.srvPort.Text,
		srvSpan:   u.srvSpan.Text,
		cliPort:   u.cliPort.Text,
		cliSpan:   u.cliSpan.Text,
		mtu:       u.mtu.Text,
		socks:     u.socks.Text,
		forwards:  u.forwards.Text,
		firewall:  u.firewall.Checked,
	})
}

func (u *ui) applyConfig(cfg config.Config) {
	u.base = cfg
	u.applyLogLevel(cfg.LogLevel)
	u.vps.SetText(cfg.Carrier.VPSIP)
	u.key.SetText(cfg.Auth.Key)
	u.trans.SetSelected(string(cfg.Transport))
	u.srvPort.SetText(strconv.Itoa(int(cfg.Carrier.ServerPort)))
	u.srvSpan.SetText(strconv.Itoa(cfg.Carrier.ServerPortSpan))
	u.cliPort.SetText(strconv.Itoa(int(cfg.Carrier.ClientPort)))
	u.cliSpan.SetText(strconv.Itoa(cfg.Carrier.ClientPortSpan))
	u.mtu.SetText(strconv.Itoa(cfg.Carrier.MTU))
	u.socks.SetText(cfg.Client.Socks5Listen)
	u.forwards.SetText(forwardsToText(cfg.Client.Forwards))
	u.firewall.SetChecked(cfg.Firewall.Manage != config.FirewallNo)
	u.syncLAN()
}

// parseConfig decodes YAML config bytes over the defaults, exactly as the CLI's
// config.Load does — so a key absent from the file keeps its default instead of
// becoming a zero value.
func parseConfig(raw []byte) (config.Config, error) {
	cfg := config.Default()
	err := yaml.Unmarshal(raw, &cfg)
	return cfg, err
}

// applyRaw parses YAML config bytes and populates the form from the result.
// Every key in the file lands in u.base, including the ones with no widget, so
// Connect uses them even though they are invisible here.
func (u *ui) applyRaw(raw []byte, path string) error {
	cfg, err := parseConfig(raw)
	if err != nil {
		return err
	}
	u.cfgPath.SetText(path)
	u.applyConfig(cfg)
	u.logger.Info("config loaded", "path", path)
	// Fields are populated either way; a bad file is a warning, not a stop.
	if err := cfg.Validate(); err != nil {
		u.logger.Warn("config needs fixing before connecting", "err", err)
	}
	return nil
}

// autoLoadConfig loads a config sitting next to the executable (or in the
// working directory) at startup, mirroring what the CLI does when -config is
// omitted. Without this, the settings that have no widget — kcp tuning,
// tcp_flags, seq_mode, interface, log_level — would stay at their defaults until
// the user thought to press Load. A missing file is normal: keep the defaults
// and say nothing.
func (u *ui) autoLoadConfig() {
	for _, path := range autoConfigPaths() {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := u.applyRaw(raw, path); err != nil {
			u.logger.Warn("ignoring unparseable config", "path", path, "err", err)
			continue
		}
		return
	}
}

// autoConfigPaths lists the files autoLoadConfig will try, in order: next to the
// binary first (how the released zip is laid out), then the working directory.
func autoConfigPaths() []string {
	names := []string{"client.yaml", "gfk.yaml"}
	var paths []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, n := range names {
			paths = append(paths, filepath.Join(dir, n))
		}
	}
	return append(paths, names...)
}

func (u *ui) loadConfig() {
	d := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil {
			u.logger.Error("open config failed", "err", err)
			return
		}
		if rc == nil {
			return // cancelled
		}
		defer rc.Close()
		raw, err := io.ReadAll(rc)
		if err != nil {
			u.logger.Error("read config failed", "err", err)
			return
		}
		if err := u.applyRaw(raw, localPath(rc.URI())); err != nil {
			u.logger.Error("parse config failed", "err", err)
		}
	}, u.win)
	d.SetFilter(storage.NewExtensionFileFilter([]string{".yaml", ".yml"}))
	u.showFileDialog(d, false)
}

func (u *ui) saveConfig() {
	cfg, err := u.buildConfig()
	if err != nil {
		u.logger.Error("cannot save invalid config", "err", err)
		return
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		u.logger.Error("marshal failed", "err", err)
		return
	}
	d := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil {
			u.logger.Error("save config failed", "err", err)
			return
		}
		if wc == nil {
			return // cancelled
		}
		defer wc.Close()
		if _, err := wc.Write(out); err != nil {
			u.logger.Error("write config failed", "err", err)
			return
		}
		path := localPath(wc.URI())
		u.cfgPath.SetText(path)
		u.logger.Info("config saved", "path", path)
	}, u.win)
	d.SetFilter(storage.NewExtensionFileFilter([]string{".yaml", ".yml"}))
	u.showFileDialog(d, true)
}

// showFileDialog seeds the chooser from whatever is in the config-path field and
// opens it at a usable size. Resize must follow Show: FileDialog.Resize consults
// MinSize, which panics before the dialog has been built (fyne v2.8.0).
func (u *ui) showFileDialog(d *dialog.FileDialog, save bool) {
	if p := strings.TrimSpace(u.cfgPath.Text); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if lister, err := storage.ListerForURI(storage.NewFileURI(filepath.Dir(p))); err == nil {
			d.SetLocation(lister)
		}
		if save {
			d.SetFileName(filepath.Base(p))
		}
	}
	d.Show()
	d.Resize(fyne.NewSize(720, 520))
}

// localPath turns a file:// URI from the chooser into an OS path.
func localPath(u fyne.URI) string {
	if u == nil {
		return ""
	}
	return filepath.FromSlash(u.Path())
}

// ---- log pane ----

// appendLog adds one already-formatted record to the log pane. Must run on the
// Fyne goroutine.
func (u *ui) appendLog(level slog.Level, line string) {
	seg := &widget.TextSegment{Text: line, Style: widget.RichTextStyle{ColorName: logColorName(level)}}
	u.logView.Segments = append(u.logView.Segments, seg)
	if n := len(u.logView.Segments); n > maxLogLines {
		u.logView.Segments = append([]widget.RichTextSegment(nil), u.logView.Segments[n-maxLogLines:]...)
	}
	u.logView.Refresh()
	if u.autoScroll.Checked {
		u.logScroll.ScrollToBottom()
	}
}

func logColorName(level slog.Level) fyne.ThemeColorName {
	switch {
	case level >= slog.LevelError:
		return theme.ColorNameError
	case level >= slog.LevelWarn:
		return theme.ColorNameWarning
	case level < slog.LevelInfo:
		return theme.ColorNameDisabled
	default:
		return theme.ColorNameForeground
	}
}

func (u *ui) clearLog() {
	u.logView.Segments = nil
	u.logView.Refresh()
	u.logScroll.Refresh()
}

func (u *ui) copyLog() {
	lines := make([]string, 0, len(u.logView.Segments))
	for _, s := range u.logView.Segments {
		lines = append(lines, s.Textual())
	}
	fyne.CurrentApp().Clipboard().SetContent(strings.Join(lines, "\n"))
}

// gfkTheme keeps disabled text legible — Fyne's default disabled grey is nearly
// the background colour — while still reading as greyed out, and pins
// error/warning to the app's palette. With dimInputs set it also greys the entry
// backgrounds, which Fyne itself does not vary by disabled state; the settings
// block switches to that variant while the tunnel runs.
type gfkTheme struct {
	fyne.Theme

	dimInputs bool
}

func (t gfkTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	light := v == theme.VariantLight
	switch n {
	case theme.ColorNameDisabled:
		// Mid grey: paler than the light-theme foreground (#565656), darker than
		// the dark-theme one (#f3f3f3), so both read as dimmed but readable.
		return color.NRGBA{R: 0x8c, G: 0x8c, B: 0x8c, A: 0xff}
	case theme.ColorNameInputBackground:
		if t.dimInputs {
			if light {
				return color.NRGBA{R: 0xe4, G: 0xe4, B: 0xe4, A: 0xff}
			}
			return color.NRGBA{R: 0x2b, G: 0x2b, B: 0x2f, A: 0xff}
		}
	case theme.ColorNameError:
		return colRed
	case theme.ColorNameWarning:
		return colYellow
	}
	return t.Theme.Color(n, v)
}

// ---- engine ----

type engine struct {
	cancel   context.CancelFunc
	car      *carrier.Carrier
	fwRemove func() error
}

func startEngine(cfg config.Config, applyFW bool, onState func(supervisor.State), logger *slog.Logger) (*engine, error) {
	vpsIP := net.ParseIP(cfg.Carrier.VPSIP)
	if vpsIP == nil {
		return nil, fmt.Errorf("invalid VPS IP %q", cfg.Carrier.VPSIP)
	}
	// Echo everything that took effect, including the many settings this window
	// has no field for — they come from the loaded YAML, and this line is how a
	// user confirms they were honoured.
	logger.Info("settings in effect", cfg.EffectiveAttrs()...)
	ctx, cancel := context.WithCancel(context.Background())

	span := cfg.Carrier.ClientPortSpan
	if span < 1 {
		span = 1
	}
	portEnd := cfg.Carrier.ClientPort + uint16(span) - 1

	var fwRemove func() error
	if applyFW {
		rm, err := firewall.Install(firewall.Rules{PortStart: cfg.Carrier.ClientPort, PortEnd: portEnd})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("firewall: %w", err)
		}
		fwRemove = rm
		logger.Info("firewall RST-suppression applied", "ports", fmt.Sprintf("%d-%d", cfg.Carrier.ClientPort, portEnd))
	}

	car, err := carrier.Open(carrier.Options{
		Role:           carrier.RoleClient,
		VPSIP:          vpsIP,
		ServerPort:     cfg.Carrier.ServerPort,
		ClientPort:     cfg.Carrier.ClientPort,
		ClientPortSpan: cfg.Carrier.ClientPortSpan,
		ServerPortSpan: cfg.Carrier.ServerPortSpan,
		Interface:      cfg.Carrier.Interface,
		TCPFlags:       cfg.Carrier.TCPFlags,
		SeqMode:        cfg.Carrier.SeqMode,
		Warn:           logger.Warn,
	})
	if err != nil {
		cancel()
		if fwRemove != nil {
			_ = fwRemove()
		}
		return nil, fmt.Errorf("carrier: %w", err)
	}
	logger.Info("carrier bound", logx.Addr("local_ip", car.LocalIP()), "interface", cfg.Carrier.Interface)

	params := transport.Params{
		Transport: cfg.Transport,
		Key:       cfg.Auth.Key,
		// Not cfg.Carrier.MTU: realistic mode spends 12 header bytes on the
		// timestamp option, and the IP packet must stay the same size either way.
		MTU:              cfg.TransportMTU(),
		KeepAliveSeconds: cfg.Client.KeepAliveSeconds,
		KCP:              cfg.KCP,
		QUIC:             cfg.QUIC,
	}
	remote := &carrier.Addr{IP: vpsIP, Port: cfg.Carrier.ServerPort}
	delay := time.Duration(cfg.Client.ReconnectSeconds) * time.Second
	if delay <= 0 {
		delay = 3 * time.Second
	}
	dialCount := 0
	sup := supervisor.New(func(dctx context.Context) (transport.Session, error) {
		if dialCount > 0 {
			car.RotateClientPort() // fresh source port on reconnect
			car.RotateServerPort() // rotate server port to escape a blocked one
		}
		dialCount++
		sess, err := transport.Dial(dctx, car, remote, params)
		if err != nil {
			return nil, err
		}
		if err := tunnel.Verify(sess, cfg.Auth.Key); err != nil {
			_ = sess.Close()
			return nil, err
		}
		logger.Info(string(cfg.Transport)+" tunnel established to server", logx.Peer(remote))
		return sess, nil
	}, delay, logger)
	sup.SetStateHook(onState)
	go sup.Run(ctx)

	cl := tunnel.NewClient(cfg.Client, cfg.Auth.Key, sup, logger)
	go cl.Run(ctx)

	return &engine{cancel: cancel, car: car, fwRemove: fwRemove}, nil
}

func (e *engine) stop() {
	e.cancel()
	_ = e.car.Close()
	if e.fwRemove != nil {
		_ = e.fwRemove()
	}
}

// ---- helpers ----

func entry(text string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(text)
	return e
}

func atou16(s string, def uint16) uint16 {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 && v <= 65535 {
		return uint16(v)
	}
	return def
}

func atoiDef(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v >= 0 {
		return v
	}
	return def
}

func parseForwards(s string) ([]config.Forward, error) {
	var fs []config.Forward
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad forward %q (want: proto listen targetport)", ln)
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("bad target port in %q", ln)
		}
		fs = append(fs, config.Forward{Proto: parts[0], Listen: parts[1], TargetPort: uint16(port)})
	}
	return fs, nil
}

func forwardsToText(fs []config.Forward) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "%s %s %d\n", f.Proto, f.Listen, f.TargetPort)
	}
	return b.String()
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// uiLogHandler is an slog.Handler that renders records into the log pane.
type uiLogHandler struct {
	level  slog.Level
	append func(slog.Level, string)
}

func (h *uiLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *uiLogHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %-5s %s", r.Time.Format("15:04:05"), r.Level.String(), r.Message)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "" { // elided attr, e.g. a peer address hidden by the log level
			return true
		}
		fmt.Fprintf(&sb, "  %s=%v", a.Key, a.Value.Any())
		return true
	})
	line, level := sb.String(), r.Level
	fyne.Do(func() { h.append(level, line) })
	return nil
}

func (h *uiLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *uiLogHandler) WithGroup(string) slog.Handler      { return h }
