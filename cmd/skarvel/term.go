package main

import (
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The terminal layer is deliberately standard-library only: plain ANSI escape
// sequences, no curses database, no third-party TUI framework. Every terminal
// skarvel is likely to meet (xterm descendants, macOS Terminal, iTerm2,
// Windows Terminal, conhost with VT processing) understands this subset.

const (
	escAltScreenOn  = "\x1b[?1049h"
	escAltScreenOff = "\x1b[?1049l"
	escHideCursor   = "\x1b[?25l"
	escShowCursor   = "\x1b[?25h"
	escHome         = "\x1b[H"
	escClearLine    = "\x1b[K"
	escClearBelow   = "\x1b[J"
	escSyncBegin    = "\x1b[?2026h" // synchronized output: no tearing where supported,
	escSyncEnd      = "\x1b[?2026l" // ignored everywhere else
	escReset        = "\x1b[0m"
)

// style is an SGR parameter list such as "1;31". The zero value is unstyled.
type style string

const (
	stNone    style = ""
	stBold    style = "1"
	stDim     style = "2"
	stRed     style = "31"
	stGreen   style = "32"
	stYellow  style = "33"
	stBlue    style = "34"
	stMagenta style = "35"
	stCyan    style = "36"
	stGray    style = "90"
	stBRed    style = "1;91"
	stBYellow style = "1;93"
	stBGreen  style = "1;92"
	stBCyan   style = "1;96"
	stBWhite  style = "1;97"
	stBadgeR  style = "1;97;41" // white on red
	stBadgeY  style = "1;30;43" // black on yellow
	stBadgeC  style = "1;30;46" // black on cyan
	stBadgeG  style = "1;30;42" // black on green
)

// palette applies styles, or does nothing when colour is off.
type palette struct{ on bool }

func (p palette) s(st style, text string) string {
	if !p.on || st == stNone || text == "" {
		return text
	}
	return "\x1b[" + string(st) + "m" + text + escReset
}

// colorWanted honours the NO_COLOR convention (https://no-color.org) and a
// dumb terminal, then asks whether f is a terminal at all.
func colorWanted(f *os.File) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTTY(f) && enableVT(f)
}

// termSize reports the terminal's columns and rows, falling back to $COLUMNS /
// $LINES and finally to 80x24.
func termSize(f *os.File) (w, h int) {
	if w, h, ok := querySize(f); ok && w > 0 && h > 0 {
		return w, h
	}
	w, _ = strconv.Atoi(os.Getenv("COLUMNS"))
	h, _ = strconv.Atoi(os.Getenv("LINES"))
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return w, h
}

// width is the number of terminal columns s occupies. Skarvel only ever prints
// repository names, paths, URLs and its own box-drawing glyphs, all of which
// are one column per rune.
func width(s string) int { return utf8.RuneCountInString(s) }

// truncate cuts s to at most n columns, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if width(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// sanitize removes control characters (including ESC) from text that came
// from the network, so a hostile repository name or log line can never inject
// escape sequences into the analyst's terminal.
func sanitize(s string) string {
	if strings.IndexFunc(s, isControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return ' '
		case isControl(r):
			return -1
		}
		return r
	}, s)
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }

// line builds one row of the screen to an exact width: text is clipped once
// the width is reached, and fill pads the remainder. Width is tracked on the
// plain text, so styling never disturbs alignment.
type line struct {
	p   palette
	b   strings.Builder
	max int
	w   int
}

func newLine(p palette, max int) *line { return &line{p: p, max: max} }

func (l *line) add(st style, text string) *line {
	room := l.max - l.w
	if room <= 0 || text == "" {
		return l
	}
	text = truncate(sanitize(text), room)
	l.b.WriteString(l.p.s(st, text))
	l.w += width(text)
	return l
}

// addRight right-aligns text against the line's end, leaving at least one
// space; it is dropped entirely if it does not fit.
func (l *line) addRight(st style, text string) *line {
	gap := l.max - l.w - width(text)
	if gap < 1 {
		return l
	}
	l.b.WriteString(strings.Repeat(" ", gap))
	l.w += gap
	return l.add(st, text)
}

func (l *line) fill() string {
	if l.w < l.max {
		l.b.WriteString(strings.Repeat(" ", l.max-l.w))
		l.w = l.max
	}
	return l.b.String()
}

func (l *line) String() string { return l.b.String() }
