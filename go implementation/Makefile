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

.PHONY: all cli-linux cli-windows gui test clean

all: cli-linux cli-windows

cli-linux:
	CGO_ENABLED=0 GOOS=linux $(BUILD) -o dist/gfk ./cmd/gfk

cli-windows:
	CGO_ENABLED=0 GOOS=windows $(BUILD) -o dist/gfk.exe ./cmd/gfk

# -H windowsgui makes it a GUI-subsystem binary, so double-clicking it does not
# also open a console window behind the app.
gui:
	CGO_ENABLED=1 go build -tags gui -trimpath -ldflags "$(LDFLAGS) -H windowsgui" -o dist/gfk-windows-GUI.exe ./cmd/gfk-gui

test:
	go test ./...
	go test -tags gui ./cmd/gfk-gui

clean:
	rm -rf dist
