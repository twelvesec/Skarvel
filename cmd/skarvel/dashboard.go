package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"skarvel/internal/criteria"
	"skarvel/internal/event"
)

// The dashboard is the live view of a hunt. Like the old one-line progress
// indicator it is purely a subscriber of the event bus, writes only to stderr
// and never reaches stdout or the output file: the report is identical whether
// or not anyone watched the run.

const (
	maxActivity = 500
	frameEvery  = 120 * time.Millisecond
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// displayMode selects how much of the dashboard reaches the terminal.
type displayMode int

const (
	modeSilent displayMode = iota // not a terminal: tally only, draw nothing
	modeLine                      // --plain on a terminal: one status line
	modeFull                      // full-screen dashboard
)

type repoState struct {
	name    string
	verdict string
	score   int
	lead    bool
	tiers   map[string]int
	at      time.Time
}

type activity struct {
	at   time.Time
	tag  string
	st   style
	text string
}

// dash holds everything the hunt has told us so far. All mutation happens on
// the goroutine running loop; other goroutines talk to it through notices.
type dash struct {
	p        palette
	mode     displayMode
	iocs     []string
	target   string // single-repository mode
	platform string
	started  time.Time

	examined   int
	hits       int
	discovered int
	promoted   int
	queued     int
	round      int
	repos      map[string]*repoState
	hitSeen    map[string]bool
	current    string
	status     string
	statusSt   style
	finished   bool
	log        []activity
	frameCount int

	notices chan string

	// showActivity adds the activity feed beside the detections (-a).
	showActivity bool

	outMu  sync.Mutex
	out    io.Writer
	size   func() (int, int)
	lastW  int
	lastH  int
	closed bool
	once   sync.Once
}

func newDash(p palette, mode displayMode, iocs []string, platform string, started time.Time) *dash {
	return &dash{
		p: p, mode: mode, iocs: iocs, platform: platform, started: started,
		repos: map[string]*repoState{}, hitSeen: map[string]bool{},
		status: "hunting", statusSt: stBCyan,
		notices: make(chan string, 4),
	}
}

// notify shows a status message (such as "interrupted") from any goroutine.
func (d *dash) notify(msg string) {
	select {
	case d.notices <- msg:
	default:
	}
}

// loop consumes events until the bus closes, redrawing on a timer so a burst
// of events costs one frame, not hundreds.
func (d *dash) loop(events <-chan event.Event) {
	d.enter()
	defer d.leave()
	tick := time.NewTicker(frameEvery)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-events:
			if !ok {
				d.finished = true
				d.draw()
				return
			}
			d.apply(e)
		case msg := <-d.notices:
			d.status, d.statusSt = msg, stBYellow
			d.push(activity{at: time.Now(), tag: "notice", st: stBYellow, text: msg})
			d.draw()
		case <-tick.C:
			d.frameCount++
			d.draw()
		}
	}
}

func (d *dash) enter() {
	if d.mode != modeFull {
		return
	}
	d.outMu.Lock()
	defer d.outMu.Unlock()
	io.WriteString(d.out, escAltScreenOn+escHideCursor+"\x1b[2J")
}

// leave restores the terminal. It is safe to call from any goroutine, any
// number of times -- including from the second Ctrl-C just before os.Exit.
func (d *dash) leave() {
	d.once.Do(func() {
		d.outMu.Lock()
		defer d.outMu.Unlock()
		d.closed = true
		switch d.mode {
		case modeFull:
			io.WriteString(d.out, escAltScreenOff+escShowCursor)
		case modeLine:
			io.WriteString(d.out, "\r"+escClearLine)
		}
	})
}

func (d *dash) push(a activity) {
	d.log = append(d.log, a)
	if len(d.log) > maxActivity {
		d.log = append(d.log[:0], d.log[len(d.log)-maxActivity:]...)
	}
}

func (d *dash) repo(name string) *repoState {
	r := d.repos[name]
	if r == nil {
		r = &repoState{name: name, tiers: map[string]int{}}
		d.repos[name] = r
	}
	return r
}

func tierStyle(t string) style {
	switch t {
	case "A":
		return stBRed
	case "B":
		return stRed
	case "C":
		return stYellow
	}
	return stGray
}

func verdictStyle(v string) style {
	switch v {
	case criteria.VerdictMalicious.String():
		return stBRed
	case criteria.VerdictReview.String():
		return stBYellow
	case "WARNED":
		return stCyan
	}
	return stGreen
}

func leadTag(lead bool) string {
	if lead {
		return " [lead]"
	}
	return ""
}

// apply folds one event into the dashboard state.
func (d *dash) apply(e event.Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	a := activity{at: e.Time}
	switch e.Kind {
	case event.KindLog:
		a.tag, a.st, a.text = "log", stGray, e.Message
		if e.Repo != "" {
			a.text = e.Repo + ": " + e.Message
		}
	case event.KindDiscover:
		if e.NodeKind == "repo" {
			d.discovered++
		}
		a.tag, a.st = "found", stBlue
		a.text = strings.TrimSpace(e.NodeKind+" "+e.Node) + leadTag(e.Lead)
		if e.Message != "" {
			a.text += " · " + e.Message
		}
	case event.KindVisit:
		d.current = fmt.Sprintf("%s %s · hop %d", e.NodeKind, e.Node, e.Hops)
		if e.Lead {
			d.current += " [lead]"
		}
		a.tag, a.st, a.text = "visit", stCyan, d.current
	case event.KindFinding:
		key := e.Repo + "\x00" + e.Path + "\x00" + e.Signal
		if d.hitSeen[key] {
			return // the same hit again (search index, then clone): already shown
		}
		d.hitSeen[key] = true
		d.hits++
		if e.Repo != "" {
			d.repo(e.Repo).tiers[e.Tier]++
		}
		a.tag, a.st = "hit "+e.Tier, tierStyle(e.Tier)
		a.text = e.Repo
		if e.Path != "" {
			a.text += "/" + strings.TrimPrefix(e.Path, "/")
		}
		if e.Signal != "" {
			a.text += " · " + e.Signal
		}
	case event.KindVerdict:
		d.examined++
		r := d.repo(e.Repo)
		r.verdict, r.score, r.lead, r.at = e.Verdict, e.Score, e.Lead, e.Time
		a.tag, a.st = strings.ToLower(e.Verdict), verdictStyle(e.Verdict)
		a.text = fmt.Sprintf("%s · score %d%s", e.Repo, e.Score, leadTag(e.Lead))
		if e.Message != "" {
			a.text += " · " + e.Message
		}
	case event.KindIndicator:
		if strings.HasPrefix(e.Message, "promoted") {
			d.promoted++
		} else {
			d.queued++
		}
		a.tag, a.st, a.text = "ioc", stMagenta, e.Message
	case event.KindReview:
		a.tag, a.st, a.text = "review", stYellow, e.Message
		if e.Repo != "" {
			a.text = e.Repo + ": " + e.Message
		}
	case event.KindRound:
		d.round = e.Score
		a.tag, a.st, a.text = "round", stDim, e.Message
	case event.KindHalt:
		d.status, d.statusSt = "halted: "+e.Message, stBRed
		a.tag, a.st, a.text = "halt", stBRed, e.Message
	case event.KindDone:
		if !strings.HasPrefix(d.status, "halted") && d.statusSt != stBYellow {
			d.status, d.statusSt = "finishing", stBGreen
		}
		a.tag, a.st, a.text = "done", stBGreen, e.Message
	case event.KindBudget:
		return
	default:
		a.tag, a.st, a.text = string(e.Kind), stGray, e.Message
	}
	d.push(a)
}

// detections are the repositories with a non-clean verdict, the most severe
// and then the most recent first.
func (d *dash) detections() []*repoState {
	var out []*repoState
	for _, r := range d.repos {
		if r.verdict == criteria.VerdictMalicious.String() || r.verdict == criteria.VerdictReview.String() {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].verdict != out[j].verdict {
			return out[i].verdict == criteria.VerdictMalicious.String()
		}
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.After(out[j].at)
		}
		return out[i].name < out[j].name
	})
	return out
}

func (d *dash) count(verdict string) int {
	n := 0
	for _, r := range d.repos {
		if r.verdict == verdict {
			n++
		}
	}
	return n
}

func (d *dash) draw() {
	d.outMu.Lock()
	defer d.outMu.Unlock()
	if d.closed || d.out == nil {
		return
	}
	now := time.Now()
	switch d.mode {
	case modeLine:
		w, _ := d.size()
		l := newLine(d.p, w-1).add(stCyan, "[*] ").
			add(stNone, fmt.Sprintf("%s… %d repos examined, %d flagged, %s", d.status,
				d.examined, d.count("MALICIOUS")+d.count("REVIEW"), fmtDur(now.Sub(d.started))))
		io.WriteString(d.out, "\r"+escClearLine+l.String())
	case modeFull:
		w, h := d.size()
		var b strings.Builder
		b.WriteString(escSyncBegin)
		if w != d.lastW || h != d.lastH {
			b.WriteString("\x1b[2J")
			d.lastW, d.lastH = w, h
		}
		for i, row := range d.frame(w, h, now) {
			fmt.Fprintf(&b, "\x1b[%d;1H%s%s", i+1, row, escClearLine)
		}
		b.WriteString(escSyncEnd)
		io.WriteString(d.out, b.String())
	}
}

// frame renders the whole screen as exactly h rows of exactly w columns.
func (d *dash) frame(w, h int, now time.Time) []string {
	if w < 20 || h < 3 {
		return []string{newLine(d.p, w).add(stBCyan, "skarvel").fill()}
	}
	var rows []string
	add := func(r ...string) { rows = append(rows, r...) }
	blank := strings.Repeat(" ", w)
	compact := w < 64 || h < 22

	add(d.header(w, now))
	if !compact {
		add(d.p.s(stGray, strings.Repeat("─", w)))
		if d.target != "" {
			add(d.kv(w, "repo", d.target, stBWhite))
		}
		if len(d.iocs) > 0 {
			add(d.kv(w, "IOC", strings.Join(d.iocs, ", "), stBWhite))
		}
	}
	add(d.nowLine(w))
	if compact {
		add(d.statsCompact(w))
	} else {
		add(blank)
		add(d.statTiles(w)...)
		add(blank)
	}

	footer := d.footer(w)
	room := h - len(rows) - 1
	if room >= 3 {
		add(d.panels(w, room)...)
	}
	for len(rows) < h-1 {
		add(blank)
	}
	rows = rows[:h-1]
	add(footer)
	return rows
}

func (d *dash) header(w int, now time.Time) string {
	l := newLine(d.p, w)
	l.add(stBadgeC, " ◆ SKARVEL ").add(stDim, " repository IOC hunter")
	spin := spinner[d.frameCount%len(spinner)]
	if d.finished {
		spin = "✔"
	}
	right := fmt.Sprintf("%s  %s %s  %s ", d.platform, spin, d.status, fmtDur(now.Sub(d.started)))
	if width(right)+l.w+2 > w {
		right = fmt.Sprintf("%s %s ", spin, fmtDur(now.Sub(d.started)))
	}
	gap := w - l.w - width(right)
	if gap >= 1 {
		l.add(stNone, strings.Repeat(" ", gap))
		parts := strings.SplitN(right, "  ", 3)
		if len(parts) == 3 {
			l.add(stMagenta, parts[0]).add(stNone, "  ").add(d.statusSt, parts[1]).add(stNone, "  ").add(stBWhite, parts[2])
		} else {
			l.add(stBWhite, right)
		}
	}
	return l.fill()
}

func (d *dash) kv(w int, k, v string, st style) string {
	return newLine(d.p, w).add(stGray, fmt.Sprintf("  %-4s ", k)).add(st, v).fill()
}

func (d *dash) nowLine(w int) string {
	cur := d.current
	switch {
	case d.finished:
		cur = "hunt complete · preparing report"
	case cur == "":
		cur = "checking search canary and seeding indicators…"
	}
	return newLine(d.p, w).add(stGray, "  NOW  ").add(stCyan, spinner[d.frameCount%len(spinner)]+" ").add(stNone, cur).fill()
}

type stat struct {
	label string
	value int
	st    style
}

func (d *dash) stats() []stat {
	mal, rev := d.count("MALICIOUS"), d.count("REVIEW")
	malSt, revSt := stGray, stGray
	if mal > 0 {
		malSt = stBRed
	}
	if rev > 0 {
		revSt = stBYellow
	}
	return []stat{
		{"EXAMINED", d.examined, stBWhite},
		{"MALICIOUS", mal, malSt},
		{"REVIEW", rev, revSt},
		{"HITS", d.hits, stBWhite},
		{"DISCOVERED", d.discovered, stBWhite},
		{"NEW IOCs", d.promoted, stMagenta},
		{"ROUND", d.round, stBWhite},
	}
}

func (d *dash) statTiles(w int) []string {
	ss := d.stats()
	n := len(ss)
	for n > 1 && (w-2)/n < 11 {
		n--
	}
	ss = ss[:n]
	cell := (w - 2) / n
	top, bot := newLine(d.p, w).add(stNone, "  "), newLine(d.p, w).add(stNone, "  ")
	for _, s := range ss {
		v := strconv.Itoa(s.value)
		top.add(s.st, fmt.Sprintf("%-*s", cell, " "+v))
		bot.add(stGray, fmt.Sprintf("%-*s", cell, " "+s.label))
	}
	return []string{top.fill(), bot.fill()}
}

func (d *dash) statsCompact(w int) string {
	l := newLine(d.p, w).add(stNone, " ")
	for i, s := range d.stats()[:4] {
		if i > 0 {
			l.add(stGray, " · ")
		}
		l.add(s.st, strconv.Itoa(s.value)).add(stGray, " "+strings.ToLower(s.label))
	}
	return l.fill()
}

// panels lays out the detections box in h rows, or, with -a, the activity and
// detections boxes: side by side (activity left, detections right) on a wide
// terminal, stacked on a narrow one.
func (d *dash) panels(w, h int) []string {
	det := d.detections()
	detTitle := fmt.Sprintf("DETECTIONS (%d)", len(det))
	if !d.showActivity {
		return d.box(detTitle, d.detectionRows(det, w-4, h-2), w, h)
	}
	if w >= 100 {
		rw := w * 2 / 5
		left := d.box("ACTIVITY", d.activityRows(w-rw-4, h-2), w-rw, h)
		right := d.box(detTitle, d.detectionRows(det, rw-4, h-2), rw, h)
		out := make([]string, h)
		for i := range out {
			out[i] = left[i] + right[i]
		}
		return out
	}
	detH := len(det) + 2
	if len(det) == 0 {
		detH = 3
	}
	if max := h / 2; detH > max {
		detH = max
	}
	if detH < 3 {
		detH = 3
	}
	if h-detH < 3 {
		return d.box(detTitle, d.detectionRows(det, w-4, h-2), w, h)
	}
	out := d.box(detTitle, d.detectionRows(det, w-4, detH-2), w, detH)
	return append(out, d.box("ACTIVITY", d.activityRows(w-4, h-detH-2), w, h-detH)...)
}

func (d *dash) detectionRows(det []*repoState, w, n int) []string {
	if n <= 0 {
		return nil
	}
	var rows []string
	for i, r := range det {
		if len(rows) == n {
			break
		}
		if len(rows) == n-1 && len(det)-i > 1 {
			rows = append(rows, newLine(d.p, w).add(stDim, fmt.Sprintf("… %d more", len(det)-i)).fill())
			break
		}
		l := newLine(d.p, w)
		if r.verdict == criteria.VerdictMalicious.String() {
			l.add(stBadgeR, " MAL ")
		} else {
			l.add(stBadgeY, " REV ")
		}
		var tiers []string
		for _, t := range []string{"A", "B", "C"} {
			if c := r.tiers[t]; c > 0 {
				tiers = append(tiers, d.p.s(tierStyle(t), fmt.Sprintf("%s%d", t, c)))
			}
		}
		right := fmt.Sprintf("score %d", r.score)
		if r.lead {
			right = "lead · " + right
		}
		tierW := 0
		for _, t := range []string{"A", "B", "C"} {
			if c := r.tiers[t]; c > 0 {
				tierW += len(strconv.Itoa(c)) + 2
			}
		}
		nameW := w - 5 - 1 - width(right) - tierW - 2
		l.add(stNone, " ").add(stBWhite, truncate(r.name, nameW))
		if tierW > 0 && l.w+tierW+width(right)+1 <= w {
			l.add(stNone, strings.Repeat(" ", w-l.w-tierW-width(right)-1))
			for _, t := range tiers {
				l.b.WriteString(t + " ")
			}
			l.w += tierW
			l.add(stGray, right)
		} else {
			l.addRight(stGray, right)
		}
		rows = append(rows, l.fill())
	}
	return rows
}

func (d *dash) activityRows(w, n int) []string {
	if n <= 0 {
		return nil
	}
	start := len(d.log) - n
	if start < 0 {
		start = 0
	}
	var rows []string
	for _, a := range d.log[start:] {
		l := newLine(d.p, w).add(stGray, a.at.Format("15:04:05")+" ")
		l.add(a.st, fmt.Sprintf("%-9s", a.tag)).add(stNone, " "+a.text)
		rows = append(rows, l.fill())
	}
	if len(rows) == 0 {
		rows = append(rows, newLine(d.p, w).add(stDim, "waiting for the first event…").fill())
	}
	return rows
}

// box frames rows (each already exactly w-4 wide, or fewer rows than fit)
// in a rounded border of exactly w by h.
func (d *dash) box(title string, rows []string, w, h int) []string {
	inner := w - 4
	out := make([]string, 0, h)
	title = truncate(title, w-6)
	out = append(out, d.p.s(stGray, "╭─ ")+d.p.s(stBold, title)+d.p.s(stGray, " "+strings.Repeat("─", max(0, w-width(title)-5))+"╮"))
	side := d.p.s(stGray, "│")
	for i := 0; i < h-2; i++ {
		r := strings.Repeat(" ", inner)
		if i < len(rows) {
			r = rows[i]
		}
		out = append(out, side+" "+r+" "+side)
	}
	out = append(out, d.p.s(stGray, "╰"+strings.Repeat("─", max(0, w-2))+"╯"))
	return out
}

func (d *dash) footer(w int) string {
	l := newLine(d.p, w).add(stBadgeC, " ctrl-c ").add(stDim, " stop and write the results found so far")
	l.addRight(stDim, "skarvel "+version+" ")
	return l.fill()
}

// fmtDur renders a duration as H:MM:SS.
func fmtDur(t time.Duration) string {
	if t < 0 {
		t = 0
	}
	s := int(t / time.Second)
	return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
}
