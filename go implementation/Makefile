# gfk build targets. GUI needs cgo + mingw-w64; CLI is cgo-free.
#
# The flags below are the same ones .github/workflows/release.yml uses, so a
# local build matches a released one instead of being a third larger:
#   -trimpath  strips local filesystem paths (and your username) out of the
#              binary, which also makes builds reproducible
#   -s -w      drop the symbol table and DWARF debug info — nothing debugs a
#              release build, and this is most of the size
# Keep the two in step: if you change one, change the other.
LDFLAGS := -s -w
BUILD   := go build -trimpath -ldflags "$(LDFLAGS)"

# Windows resource metadata for the GUI. internal/version/version.go stays the
# single place a release is bumped, so the numbers are read back out of it here
# rather than duplicated: FixedFileInfo wants four integers, StringFileInfo wants
# the display string, and both come from that one constant.
VERSION   := $(shell sed -n 's/^[[:space:]]*Version = "\(.*\)"$$/\1/p' internal/version/version.go)
VERNUM    := $(patsubst v%,%,$(VERSION))
VER_MAJOR := $(or $(word 1,$(subst ., ,$(VERNUM))),0)
VER_MINOR := $(or $(word 2,$(subst ., ,$(VERNUM))),0)
VER_PATCH := $(or $(word 3,$(subst ., ,$(VERNUM))),0)

# Pinned, because an unpinned @latest would let the resource block change shape
# between two builds of the same tag.
#
# Overridable (?=) because `go run pkg@version` always reaches the network, even
# with the module already cached, and the proxy is not reliably reachable from
# everywhere this project gets built. Two ways out:
#   make gui GOVERSIONINFO=goversioninfo   # after a one-off `go install`
#   GOPROXY=file://$(go env GOMODCACHE)/cache/download make gui
GOVERSIONINFO ?= go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.5.0

# _windows_amd64 is a Go build constraint expressed in the filename: the linker
# picks this up only for that target, so it cannot leak into the Linux CLI.
SYSO := cmd/gfk-gui/resource_windows_amd64.syso
# Optional — drop a cmd/gfk-gui/icon.ico in and it gets embedded. The project
# ships no icon today, so the flag is omitted rather than pointing at nothing.
ICON := $(wildcard cmd/gfk-gui/icon.ico)

.PHONY: all cli-linux cli-windows gui syso test clean

all: cli-linux cli-windows

cli-linux:
	CGO_ENABLED=0 GOOS=linux $(BUILD) -o dist/gfk ./cmd/gfk

cli-windows:
	CGO_ENABLED=0 GOOS=windows $(BUILD) -o dist/gfk.exe ./cmd/gfk

syso: $(SYSO)

$(SYSO): cmd/gfk-gui/versioninfo.json cmd/gfk-gui/gfk-gui.manifest internal/version/version.go
	$(GOVERSIONINFO) -64 \
	  -manifest cmd/gfk-gui/gfk-gui.manifest \
	  $(if $(ICON),-icon $(ICON),) \
	  -ver-major $(VER_MAJOR) -ver-minor $(VER_MINOR) -ver-patch $(VER_PATCH) -ver-build 0 \
	  -product-ver-major $(VER_MAJOR) -product-ver-minor $(VER_MINOR) -product-ver-patch $(VER_PATCH) -product-ver-build 0 \
	  -file-version "$(VERSION)" -product-version "$(VERSION)" \
	  -o $(SYSO) cmd/gfk-gui/versioninfo.json

# -H windowsgui makes it a GUI-subsystem binary, so double-clicking it does not
# also open a console window behind the app.
gui: $(SYSO)
	CGO_ENABLED=1 go build -tags gui -trimpath -ldflags "$(LDFLAGS) -H windowsgui" -o dist/gfk-windows-GUI.exe ./cmd/gfk-gui

test:
	go test ./...
	go test -tags gui ./cmd/gfk-gui

clean:
	rm -rf dist
	rm -f $(SYSO)
