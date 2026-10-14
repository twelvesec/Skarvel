package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"skarvel/internal/event"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func visible(s string) string { return ansi.ReplaceAllString(s, "") }

func busyDash(color bool) *dash {
	t0 := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	d := newDash(palette{on: color}, modeFull, []string{"codeprettier.pro"}, "github", t0)
	at := t0
	ev := func(e event.Event) { at = at.Add(time.Second); e.Time = at; d.apply(e) }
	ev(event.Event{Kind: event.KindDiscover, Node: "codeprettier.pro", NodeKind: "indicator", Message: "seed indicator (domain)"})
	ev(event.Event{Kind: event.KindVisit, Node: "codeprettier.pro", NodeKind: "indicator"})
	ev(event.Event{Kind: event.KindDiscover, Node: "op/lure", NodeKind: "repo", Hops: 1})
	ev(event.Event{Kind: event.KindFinding, Repo: "op/lure", Path: ".vscode/settings.json", Signal: "known-domain", Tier: "A"})
	ev(event.Event{Kind: event.KindFinding, Repo: "op/lure", Path: ".vscode/settings.json", Signal: "known-domain", Tier: "A"})
	ev(event.Event{Kind: event.KindFinding, Repo: "op/lure", Path: "backend/x.js", Signal: "eval-fetch", Tier: "B"})
	ev(event.Event{Kind: event.KindVerdict, Repo: "op/lure", Verdict: "MALICIOUS", Score: 260, Message: "1 definitive signal(s)"})
	ev(event.Event{Kind: event.KindVerdict, Repo: "dev/maybe", Verdict: "REVIEW", Score: 60, Lead: true})
	ev(event.Event{Kind: event.KindVerdict, Repo: "plain/clean", Verdict: "CLEAN"})
	ev(event.Event{Kind: event.KindIndicator, Repo: "op/lure", Message: "promoted domain indicator evil.example"})
	ev(event.Event{Kind: event.KindRound, Score: 2, Message: "round 2 closed, queue empty"})
	ev(event.Event{Kind: event.KindLog, Repo: "evil/\x1b]0;pwned\x07name", Message: "line\x1b[2Jbreak\nnext"})
	ev(event.Event{Kind: event.KindVisit, Node: "op/" + strings.Repeat("x", 300), NodeKind: "repo", Hops: 2})
	return d
}

func TestDashboardState(t *testing.T) {
	d := busyDash(false)
	hitLines := 0
	for _, a := range d.log {
		if strings.HasPrefix(a.tag, "hit") {
			hitLines++
		}
	}
	if hitLines != 2 {
		t.Errorf("duplicate finding logged: %d hit lines", hitLines)
	}
	if d.examined != 3 || d.hits != 2 || d.discovered != 1 || d.promoted != 1 || d.round != 2 {
		t.Fatalf("examined=%d hits=%d discovered=%d promoted=%d round=%d",
			d.examined, d.hits, d.discovered, d.promoted, d.round)
	}
	det := d.detections()
	if len(det) != 2 || det[0].name != "op/lure" || det[1].name != "dev/maybe" {
		t.Fatalf("detections = %+v", det)
	}
	if det[0].tiers["A"] != 1 || det[0].tiers["B"] != 1 {
		t.Errorf("tiers = %v", det[0].tiers)
	}
}

// Every frame must be exactly h rows of exactly w columns, at any size, or the
// screen tears; and nothing from the network may smuggle in an escape code.
func TestDashboardFrameGeometry(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 5, 0, 0, time.UTC)
	for _, color := range []bool{false, true} {
		d := busyDash(color)
		for _, act := range []bool{false, true} {
			d.showActivity = act
			for _, sz := range [][2]int{{20, 3}, {40, 10}, {63, 21}, {80, 24}, {99, 30}, {100, 30}, {130, 40}, {200, 60}, {19, 2}} {
				rows := d.frame(sz[0], sz[1], now)
				wantH := sz[1]
				if sz[0] < 20 || sz[1] < 3 {
					wantH = 1
				}
				if len(rows) != wantH {
					t.Fatalf("%dx%d color=%v: %d rows", sz[0], sz[1], color, len(rows))
				}
				for i, r := range rows {
					v := visible(r)
					if wantH > 1 && width(v) != sz[0] {
						t.Fatalf("%dx%d color=%v row %d is %d wide: %q", sz[0], sz[1], color, i, width(v), v)
					}
					if strings.ContainsAny(v, "\x1b\x07\n\r") {
						t.Fatalf("control character leaked into row %d: %q", i, v)
					}
					if !color && r != v {
						t.Fatalf("colour off but row %d is styled: %q", i, r)
					}
				}
			}
		}
	}
}

func TestDashboardFrameContent(t *testing.T) {
	d := busyDash(false)
	if screen := strings.Join(d.frame(120, 40, time.Now()), "\n"); strings.Contains(screen, "ACTIVITY") ||
		!strings.Contains(screen, "DETECTIONS (2)") {
		t.Fatalf("activity shown without -a, or detections missing:\n%s", screen)
	}
	d.showActivity = true
	screen := strings.Join(d.frame(120, 40, time.Date(2026, 10, 6, 12, 5, 0, 0, time.UTC)), "\n")
	for _, s := range []string{"SKARVEL", "codeprettier.pro", "DETECTIONS (2)", " MAL  op/lure", " REV  dev/maybe",
		"score 260", "lead · score 60", "ACTIVITY", "0:05:00", "evil/]0;pwnedname: line[2Jbreak next"} {
		if !strings.Contains(screen, s) {
			t.Errorf("screen missing %q:\n%s", s, screen)
		}
	}
	if os.Getenv("SKARVEL_DUMP_FRAME") != "" {
		c := busyDash(true)
		c.showActivity = true
		os.WriteFile(os.Getenv("SKARVEL_DUMP_FRAME"),
			[]byte(strings.Join(c.frame(120, 34, time.Date(2026, 10, 6, 12, 5, 0, 0, time.UTC)), "\n")+"\n"), 0o644)
	}
}

func TestLineClips(t *testing.T) {
	l := newLine(palette{}, 10).add(stNone, "abc").add(stNone, "defghijklmnop")
	if got := l.fill(); got != "abcdefghi…" {
		t.Fatalf("got %q", got)
	}
	if got := newLine(palette{}, 10).add(stNone, "ab").addRight(stNone, "xy").fill(); got != "ab      xy" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderPretty(t *testing.T) {
	r := results{
		Malicious: []repoResult{{URL: "https://github.com/op/lure", Paths: []string{"/a", "/b"}, Forged: true}},
		Verify:    []repoResult{{URL: "https://github.com/dev/maybe", Paths: []string{"/c"}}},
	}
	for _, color := range []bool{false, true} {
		out := visible(renderPretty(palette{on: color}, r, []string{"Hunt stopped early (interrupted)"},
			summary{IOCs: []string{"codeprettier.pro"}, Platform: "github", Examined: 7}, 80))
		for _, s := range []string{"═══ 1 MALICIOUS · repository confirmed",
			"https://github.com/op/lure  [forged commit timestamps]",
			"├─ /a", "└─ /b", "═══ 1 TO VERIFY · repository with weaker or unconfirmed signals",
			"└─ /c", "✖ Hunt stopped early", "7 repos examined", "codeprettier.pro"} {
			if !strings.Contains(out, s) {
				t.Errorf("color=%v: missing %q:\n%s", color, s, out)
			}
		}
	}
}

func TestParseArgsPlainAndVersion(t *testing.T) {
	c, err := parseArgs([]string{"--ioc", "x", "--plain", "-a"})
	if err != nil || !c.plain || !c.activity {
		t.Fatalf("c=%+v err=%v", c, err)
	}
	if _, err := parseArgs([]string{"--version"}); err != errVersion {
		t.Fatalf("err = %v", err)
	}
}
