//go:build !linux && !darwin && !windows

package main

import "os"

func querySize(*os.File) (w, h int, ok bool) { return 0, 0, false }

func enableVT(*os.File) bool { return true }
