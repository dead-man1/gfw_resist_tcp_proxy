//go:build gui && !windows

package main

// usableContentHeightPx is Windows-only; elsewhere the fallback window size applies.
func usableContentHeightPx() int { return 0 }
