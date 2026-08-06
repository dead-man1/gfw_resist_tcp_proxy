//go:build gui && windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	procSystemParametersInfo = user32.NewProc("SystemParametersInfoW")
	procGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
)

const (
	spiGetWorkArea   = 0x0030
	smCYCaption      = 4
	smCYSizeFrame    = 33
	smCXPaddedBorder = 92
)

type winRect struct {
	left, top, right, bottom int32
}

func getSystemMetrics(index int32) int {
	v, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(int32(v))
}

// usableContentHeightPx returns the height in physical pixels a window's content
// may occupy without the frame running under the taskbar: the monitor work area
// minus the title bar and resize borders. 0 means "unknown".
func usableContentHeightPx() int {
	var r winRect
	ok, _, _ := procSystemParametersInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0)
	if ok == 0 {
		return 0
	}
	work := int(r.bottom - r.top)
	if work <= 0 {
		return 0
	}
	frame := getSystemMetrics(smCYCaption) + 2*(getSystemMetrics(smCYSizeFrame)+getSystemMetrics(smCXPaddedBorder))
	if h := work - frame; h > 0 {
		return h
	}
	return work
}
