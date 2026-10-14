package main

import (
	"fmt"
	"strings"
	"time"
)

// summary is the run context printed above the styled report.
type summary struct {
	IOCs       []string
	Repo       string // single-repository mode: "owner/name", else empty
	Platform   string
	Elapsed    time.Duration
	Examined   int
	Discovered int
	Hits       int
	Promoted   int
}

// renderPretty is the terminal form of render: the same header card, the same
// section banners, the same repositories in the same order as the plain-text
// report, only drawn in colour. The output file always gets the plain form so
// it stays greppable and diffable.
func renderPretty(p palette, r results, warnings []string, s summary, termW int) string {
	var b strings.Builder
	w := min(max(termW, 40), 100)
	inner := w - 2
	rule := p.s(stGray, strings.Repeat("─", w-2))
	hdr := func(l *line) { b.WriteString("  " + l.fill() + "\n") }

	// Header card: run context under a pair of rules (no color in the file,
	// so the plain report uses the same shape).
	b.WriteString("\n")
	hdr(newLine(p, inner).add(stBCyan, "SKARVEL").add(stGray, " · ").add(stBold, "hunt report").
		addRight(stGray, time.Now().Format("2006-01-02 15:04")))
	b.WriteString("  " + rule + "\n")
	if s.Repo != "" {
		hdr(newLine(p, inner).add(stGray, fmt.Sprintf("%-10s", "repo")).add(stBWhite, s.Repo))
	}
	for i, ioc := range s.IOCs {
		k := "IOC"
		if i > 0 {
			k = ""
		}
		hdr(newLine(p, inner).add(stGray, fmt.Sprintf("%-10s", k)).add(stBWhite, ioc))
	}
	if s.Platform != "" {
		hdr(newLine(p, inner).add(stGray, fmt.Sprintf("%-10s", "platform")).add(stMagenta, s.Platform).
			addRight(stGray, "duration "+fmtDur(s.Elapsed)))
	}
	hdr(newLine(p, inner).add(stGray, fmt.Sprintf("%-10s", "scope")).
		add(stNone, fmt.Sprintf("%d %s examined", s.Examined, plural(s.Examined, "repo", "repos"))).add(stGray, " · ").
		add(stNone, fmt.Sprintf("%d discovered", s.Discovered)).add(stGray, " · ").
		add(stNone, fmt.Sprintf("%d hits", s.Hits)).add(stGray, " · ").
		add(stNone, fmt.Sprintf("%d new %s", s.Promoted, plural(s.Promoted, "IOC", "IOCs"))))
	b.WriteString("  " + rule + "\n\n")

	writeBody(&b, p, r)

	b.WriteString("  " + rule + "\n")
	for _, warn := range warnings {
		b.WriteString("  " + p.s(stBRed, "✖ ") + p.s(stRed, sanitize(warn)) + "\n")
	}
	b.WriteString("  " + p.s(stBYellow, "! ") + p.s(stDim, "All results are automated leads. Verify every repository manually before acting on or attributing it.") + "\n")
	return b.String()
}

// writeBody draws everything between the header card and the footer: the
// repository sections and the indicators the hunt mined. Both renderers call it,
// the file one with colour off, so the two can never disagree about content.
func writeBody(b *strings.Builder, p palette, r results) {
	writeSection(b, p, "MALICIOUS", stBRed, stRed,
		plural(len(r.Malicious), "repository confirmed", "repositories confirmed"),
		"no repository confirmed malicious", r.Malicious)

	writeSection(b, p, "TO VERIFY", stBYellow, stYellow,
		plural(len(r.Verify), "repository with weaker or unconfirmed signals", "repositories with weaker or unconfirmed signals"),
		"nothing needs manual verification", r.Verify)

	if len(r.Warned) > 0 {
		writeSection(b, p, "SELF-DECLARED", stBCyan, stCyan,
			plural(len(r.Warned), "repository whose own README warns it holds malicious code (owner's claim, unverified)",
				"repositories whose own README warns they hold malicious code (owner's claim, unverified)"),
			"", r.Warned)
	}

	writeIOCs(b, p, r)
}

// writeSection draws one banner and the repositories under it, in the
// "═══ N LABEL · caption" shape, or a reassuring one-liner when it is empty.
func writeSection(b *strings.Builder, p palette, label string, accent, caption style, captionText, emptyText string, rs []repoResult) {
	if len(rs) == 0 {
		b.WriteString("  " + p.s(stGreen, "═══ 0 "+label) + p.s(stGray, " · ") + p.s(stGreen, emptyText) + "\n\n")
		return
	}
	b.WriteString("  " + p.s(accent, fmt.Sprintf("═══ %d %s", len(rs), label)) +
		p.s(stGray, " · ") + p.s(caption, captionText) + "\n\n")
	writeRepos(b, p, rs, accent)
}

// writeRepos draws each repository: why it is listed, how the crawl reached it,
// then a tree of its flagged files, each with the signals that fired, the text
// that matched and a permalink -- enough to judge a lead before opening it.
func writeRepos(b *strings.Builder, p palette, rs []repoResult, bullet style) {
	for _, r := range rs {
		b.WriteString("  " + p.s(bullet, "●") + " " + p.s(stBold, sanitize(r.URL)))
		if r.Forged {
			b.WriteString("  " + p.s(stBYellow, "[forged commit timestamps]"))
		}
		b.WriteString("\n")

		meta := func(label, text string) {
			if text != "" {
				b.WriteString("      " + p.s(stGray, fmt.Sprintf("%-6s", label)) + p.s(stNone, sanitize(text)) + "\n")
			}
		}
		meta("why", r.Reason)
		meta("via", r.Chain)
		meta("clock", r.ForgedNote)

		paths := r.Paths
		if len(paths) > maxPathsPerRepo {
			paths = paths[:maxPathsPerRepo]
		}
		extra := len(r.Paths) - len(paths)
		for i, path := range paths {
			branch, rail := "├─ ", "│  "
			if i == len(paths)-1 && extra == 0 {
				branch, rail = "└─ ", "   "
			}
			b.WriteString("      " + p.s(stGray, branch) + p.s(stCyan, sanitize(path)) + "\n")
			writeFileDetail(b, p, "      "+p.s(stGray, rail)+"   ", r.Details[path])
		}
		if extra > 0 {
			b.WriteString("      " + p.s(stGray, "└─ … "+fmt.Sprintf("%d more %s", extra, plural(extra, "file", "files"))) + "\n")
		}
		b.WriteString("\n")
	}
}

// writeFileDetail draws the lines under one file: signals, matched text, link.
// A zero detail draws nothing, so a bare path stays a bare path.
func writeFileDetail(b *strings.Builder, p palette, indent string, d fileDetail) {
	if len(d.Signals) > 0 {
		sigs := d.Signals
		more := 0
		if len(sigs) > maxSignalsPerFile {
			more = len(sigs) - maxSignalsPerFile
			sigs = sigs[:maxSignalsPerFile]
		}
		parts := make([]string, 0, len(sigs)+1)
		for _, s := range sigs {
			parts = append(parts, p.s(tierStyle(s.Tier.String()), s.Tier.String())+" "+p.s(stNone, s.Name))
		}
		if more > 0 {
			parts = append(parts, p.s(stGray, fmt.Sprintf("+%d more", more)))
		}
		b.WriteString(indent + strings.Join(parts, p.s(stGray, " · ")) + "\n")
	}
	if d.Evidence != "" {
		b.WriteString(indent + p.s(stGray, "match ") + p.s(stDim, d.Evidence) + "\n")
	}
	if d.URL != "" {
		b.WriteString(indent + p.s(stGray, "↳ ") + p.s(stDim, d.URL) + "\n")
	}
}

// writeIOCs draws the indicators the hunt learned: those it promoted into its
// own search, and -- shorter and clearly separate -- those held for an analyst.
func writeIOCs(b *strings.Builder, p palette, r results) {
	if len(r.Promoted) == 0 {
		b.WriteString("  " + p.s(stGreen, "═══ 0 NEW IOCs") + p.s(stGray, " · ") +
			p.s(stGreen, "nothing new was mined from confirmed payloads") + "\n\n")
	} else {
		b.WriteString("  " + p.s(stMagenta, fmt.Sprintf("═══ %d NEW %s", len(r.Promoted), plural(len(r.Promoted), "IOC", "IOCs"))) +
			p.s(stGray, " · ") + p.s(stMagenta, "mined from confirmed payloads and searched (URLs defanged, secrets masked)") + "\n\n")
		writeIOCRows(b, p, r.Promoted, 0)
	}

	if total := len(r.Candidates) + r.CandidatesMore; total > 0 {
		b.WriteString("  " + p.s(stYellow, fmt.Sprintf("═══ %d IOC %s", total, plural(total, "CANDIDATE", "CANDIDATES"))) +
			p.s(stGray, " · ") + p.s(stYellow, "held for review, not searched") + "\n\n")
		writeIOCRows(b, p, r.Candidates, r.CandidatesMore)
	}
}

// writeIOCRows lays indicators out in aligned columns: kind, value, source.
func writeIOCRows(b *strings.Builder, p palette, es []iocEntry, more int) {
	const maxCol = 48
	col := 0
	for _, e := range es {
		col = max(col, min(width(e.Value), maxCol))
	}
	for _, e := range es {
		pad := strings.Repeat(" ", max(col-width(e.Value), 0))
		b.WriteString("    " + p.s(stMagenta, fmt.Sprintf("%-7s", e.Kind)) + " " +
			p.s(stBWhite, e.Value) + pad + "  " + p.s(stGray, "from "+e.Source) + "\n")
	}
	if more > 0 {
		b.WriteString("    " + p.s(stGray, fmt.Sprintf("… %d more not shown", more)) + "\n")
	}
	b.WriteString("\n")
}
