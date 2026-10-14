//go:build linux || darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func querySize(f *os.File) (w, h int, ok bool) {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0, 0, false
	}
	return int(ws.Col), int(ws.Row), true
}

// enableVT: Unix terminals interpret ANSI sequences natively.
func enableVT(*os.File) bool { return true }
