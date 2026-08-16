module github.com/GFW-knocker/gfw_resist_tcp_proxy

// The language version, i.e. the OLDEST Go that can build this module. Kept
// deliberately behind the toolchain below so a contributor on 1.25 is not shut
// out; raise it only to use a 1.26 language feature.
go 1.25.0

// The toolchain that actually builds it, pinned to an exact patch and matched by
// go-version in .github/workflows/release.yml.
//
// Not a formality: a release built with go1.25.12 on GitHub's runner was flagged
// Trojan:Win32/Wacatac.B!ml, while the same commit built locally on go1.25.2 was
// clean, and pinning is what makes "same commit, same binary" true. A bare minor
// like "1.26" floats to whatever patch is newest on build day, which is how the
// two ends drifted apart in the first place.
toolchain go1.26.6

require (
	fyne.io/fyne/v2 v2.8.0
	github.com/gopacket/gopacket v1.7.0
	github.com/quic-go/quic-go v0.60.0
	github.com/xtaci/kcp-go/v5 v5.6.72
	github.com/xtaci/smux v1.5.57
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	fyne.io/systray v1.12.2 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/FyshOS/fancyfs v0.0.1 // indirect
	github.com/anthonynsimon/bild v0.14.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.2.0 // indirect
	github.com/fredbi/uri v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fyne-io/gl-js v0.2.1-0.20260315212741-029c47fd27e8 // indirect
	github.com/fyne-io/image v0.1.1 // indirect
	github.com/fyne-io/oksvg v0.2.0 // indirect
	github.com/go-gl/gl v0.0.0-20260331235117-4566fea9a276 // indirect
	github.com/go-gl/glfw/v3.4/glfw v0.1.0-pre.1.0.20260707082822-2a407d02d01a // indirect
	github.com/go-text/render v0.2.1 // indirect
	github.com/go-text/typesetting v0.3.4 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/hack-pad/go-indexeddb v0.3.2 // indirect
	github.com/hack-pad/safejs v0.1.0 // indirect
	github.com/jeandeaual/go-locale v0.0.0-20250612000132-0ef82f21eade // indirect
	github.com/jsummers/gobmp v0.0.0-20230614200233-a9de23ed2e25 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.5.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rymdport/portal v0.4.2 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/yuin/goldmark v1.8.2 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/image v0.24.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
