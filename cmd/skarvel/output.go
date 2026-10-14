package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"skarvel/internal/criteria"
	"skarvel/internal/graph"
	"skarvel/internal/indicator"
)

// maxPathsPerRepo keeps one noisy repository from drowning the report.
const maxPathsPerRepo = 10

// maxSignalsPerFile and maxEvidenceCols keep the per-file detail to a glance.
const (
	maxSignalsPerFile = 4
	maxEvidenceCols   = 100
	maxChainCols      = 200
)

// signalTag is one signal that fired on a file, with its weight.
type signalTag struct {
	Tier criteria.Tier
	Name string
}

// fileDetail is what an analyst needs to judge one flagged file without opening
// the repository first: which signals fired and how strong they are, the text
// that matched, and a permalink pinned to the commit it was read at.
type fileDetail struct {
	Signals  []signalTag // strongest first
	Evidence string      // matched text, already safe and short; empty if withheld
	URL      string      // permalink to the line when known, else to the file

	line int // line of the finding the URL/Evidence came from; 0 = not line-anchored
}

// repoResult is one line group of the report: a repository and the files that
// carry its findings.
type repoResult struct {
	URL    string
	Paths  []string
	Forged bool // the commit history carries forged timestamps

	// Details are keyed by the entries of Paths. A path with no entry is simply
	// listed bare, so a result built by hand needs only URL and Paths.
	Details map[string]fileDetail

	Reason     string // why the repository is in its section
	Chain      string // how the crawl reached it, from the seed that found it
	ForgedNote string // the statistics behind the forged-timestamps flag
}

// iocEntry is one indicator the hunt mined, prepared for display.
type iocEntry struct {
	Kind   string
	Value  string // defanged / masked as appropriate
	Source string // "owner/repo:path" it was mined from
}

// results splits repositories into the sections of the report and carries what
// the hunt learned along the way.
type results struct {
	Malicious []repoResult
	Verify    []repoResult

	// Warned are repositories whose own README says they hold malicious code and
	// must not be run: research or victim copies of a lure. They carry the
	// campaign's files but are not operator assets.
	Warned []repoResult

	Promoted       []iocEntry // mined from confirmed payloads and added to the search
	Candidates     []iocEntry // held for review; capped at maxCandidates
	CandidatesMore int        // candidates beyond the cap
}

// classify decides which section each repository belongs in.
//
// Malicious means: actually cloned and analysed, rated MALICIOUS by the tier
// rules, and reached through evidence rather than through an identity lead.
// Everything else that carries a signal is reported for manual verification:
// a REVIEW verdict, a MALICIOUS verdict reached only via a lead, a repository
// the search index matched but the crawl never examined, and a repository
// whose only signal is forged commit timestamps.
//
// Repositories that merely document the campaign (advisories, IOC feeds,
// sample collections) are left out: they are intelligence, not compromise.
func classify(nodes []graph.Node, host string) results {
	byID := make(map[string]graph.Node, len(nodes))
	for _, n := range nodes {
		byID[graph.ID(n.Kind, n.Key)] = n
	}

	var r results
	for _, n := range nodes {
		if n.Kind != graph.KindRepo || n.Corpus {
			continue
		}
		res := toResult(n, host, byID)
		if n.Warned {
			// The owner says the repository holds malicious code on purpose (a
			// research or victim copy). Listed apart, with the evidence kept, and
			// never in MALICIOUS: the claim is unverified but so is the guilt.
			if hasEvidence(n) {
				res.Reason = "owner's notice: \"" + sanitize(n.WarnReason) + "\""
				if n.Examined && n.Verdict != criteria.VerdictClean {
					res.Reason += " · signatures alone would rate it " + n.Verdict.String()
				}
				r.Warned = append(r.Warned, res)
			}
			continue
		}
		switch {
		case !n.Examined:
			if hasEvidence(n) {
				res.Reason = "search-index hit only; the repository was not cloned"
				r.Verify = append(r.Verify, res)
			}
		case n.Verdict == criteria.VerdictMalicious && !n.Lead:
			res.Reason = "MALICIOUS · " + criteria.Assess(n.Findings).Reason
			r.Malicious = append(r.Malicious, res)
		case n.Verdict == criteria.VerdictMalicious:
			res.Reason = "rated MALICIOUS, but reached only through an identity lead"
			r.Verify = append(r.Verify, res)
		case n.Verdict == criteria.VerdictReview:
			res.Reason = "REVIEW · " + criteria.Assess(n.Findings).Reason
			r.Verify = append(r.Verify, res)
		case res.Forged:
			res.Reason = "the only signal is forged commit timestamps"
			r.Verify = append(r.Verify, res)
		}
	}
	return r
}

func hasEvidence(n graph.Node) bool {
	for _, f := range n.Findings {
		if f.Tier > criteria.TierD {
			return true
		}
	}
	return false
}

func isTimestampSignal(f criteria.Finding) bool {
	return f.Signal == "forged-timestamps" || f.Signal == "forged-persona"
}

// toResult builds one report entry. Repository names and file paths come from
// the network and may carry control characters or terminal escape sequences (git
// permits both in a filename), so they are made safe here, once, before either
// renderer or the output file sees them: `cat` of the report must be as safe as
// the colour view.
func toResult(n graph.Node, host string, byID map[string]graph.Node) repoResult {
	res := repoResult{
		URL:     sanitize(criteria.RepoURL(host, n.Key)),
		Chain:   chainOf(byID, graph.ID(n.Kind, n.Key)),
		Details: map[string]fileDetail{},
	}

	fs := append([]criteria.Finding(nil), n.Findings...)
	// Executable hits before documentary ones, strongest first, so the file
	// an analyst should open first is at the top.
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Documentary != fs[j].Documentary {
			return !fs[i].Documentary
		}
		if fs[i].Tier != fs[j].Tier {
			return fs[i].Tier > fs[j].Tier
		}
		return fs[i].Path < fs[j].Path
	})
	for _, f := range fs {
		if isTimestampSignal(f) && f.Tier > criteria.TierD {
			res.Forged = true
		}
		// Only the repository-level statistic is quoted: forged-persona findings
		// name an author identity, and in this campaign that is usually the person
		// being impersonated, not the operator.
		if f.Signal == "forged-timestamps" && f.Tier > criteria.TierD && res.ForgedNote == "" {
			res.ForgedNote = sanitize(f.Evidence)
		}
		if f.Path == "" || f.Tier <= criteria.TierD {
			continue
		}
		path := sanitize("/" + strings.TrimPrefix(f.Path, "/"))
		d, listed := res.Details[path]
		if !listed {
			res.Paths = append(res.Paths, path)
		}
		res.Details[path] = mergeDetail(d, listed, f)
	}
	return res
}

// mergeDetail folds one finding into the detail of its file. Findings arrive
// strongest first, so the first one names the file's headline; a later finding
// of the same strength replaces it only to supply what the first lacked -- a
// search-index hit has no line number, the clone that follows does.
func mergeDetail(d fileDetail, listed bool, f criteria.Finding) fileDetail {
	known := false
	for _, s := range d.Signals {
		if s.Name == f.Signal {
			known = true
		}
	}
	if !known {
		d.Signals = append(d.Signals, signalTag{Tier: f.Tier, Name: sanitize(f.Signal)})
	}
	better := !listed || (f.Line > 0 && d.line == 0 && len(d.Signals) > 0 && f.Tier >= d.Signals[0].Tier)
	if better {
		d.URL = sanitize(f.URL())
		d.Evidence = evidenceOf(f)
		d.line = f.Line
	}
	return d
}

// evidenceOf is the matched text of a finding, made safe and short for display.
// The text of a matched secret is withheld: it is a credential, and a report
// that gets pasted into a ticket should not carry one.
func evidenceOf(f criteria.Finding) string {
	if f.Signal == "indicator-secret" {
		return ""
	}
	return truncate(sanitize(strings.TrimSpace(f.Evidence)), maxEvidenceCols)
}

// chainOf renders how the crawl reached a node: the seed that started the path
// and each hop's reason, ending at the node itself. A node reached straight from
// nothing (a seed) has no chain worth showing.
func chainOf(byID map[string]graph.Node, id string) string {
	var path []graph.Node
	seen := map[string]bool{}
	for cur := id; cur != "" && !seen[cur]; {
		seen[cur] = true
		n, ok := byID[cur]
		if !ok {
			break
		}
		path = append(path, n)
		cur = n.From
	}
	if len(path) < 2 {
		return ""
	}
	// path runs target-first; the target is the repository being reported, so
	// it is left off and only the edge into it is shown.
	var b strings.Builder
	for i := len(path) - 1; i >= 1; i-- {
		b.WriteString(path[i].Kind.String() + " " + path[i].Key)
		b.WriteString(" ─[" + path[i-1].Reason + "]→ ")
	}
	b.WriteString("this repository")
	return truncate(sanitize(b.String()), maxChainCols)
}

// reportWidth is the column the plain-text report (file and no-color stdout)
// lays its rules and banners out to. It has no terminal to measure, so it
// picks a fixed, comfortable width.
const reportWidth = 72

// render produces the report text written to both the output file and, when
// color is off, stdout. It stays ANSI-free so the file keeps diffing and
// grepping cleanly; the structure (header card, section banners, file trees)
// is drawn with plain box characters instead of color.
func render(r results, warnings []string, s summary) string {
	var b strings.Builder

	writeHeader(&b, s)

	// The body is the same code the terminal view uses, with colour off, so the
	// file and the screen can never disagree about what a section contains.
	writeBody(&b, palette{}, r)

	b.WriteString("  " + strings.Repeat("─", reportWidth-2) + "\n")
	for _, w := range warnings {
		// Warnings can quote API error bodies, which are also untrusted.
		fmt.Fprintf(&b, "  [!] %s\n", wrapIndent(sanitize(w), reportWidth-6, "      "))
	}
	b.WriteString("  [i] All results are automated leads. Verify every repository\n" +
		"      manually before acting on or attributing it.\n")
	return b.String()
}

// writeHeader draws the run-context card at the top of the report.
func writeHeader(b *strings.Builder, s summary) {
	rule := "  " + strings.Repeat("─", reportWidth-2) + "\n"
	b.WriteString("\n")
	b.WriteString("  " + padBetween("SKARVEL · hunt report",
		time.Now().Format("2006-01-02 15:04"), reportWidth-2) + "\n")
	b.WriteString(rule)
	if s.Repo != "" {
		fmt.Fprintf(b, "  %-10s %s\n", "repo", sanitize(s.Repo))
	}
	for i, ioc := range s.IOCs {
		key := "IOC"
		if i > 0 {
			key = ""
		}
		fmt.Fprintf(b, "  %-10s %s\n", key, sanitize(ioc))
	}
	if s.Platform != "" {
		fmt.Fprintf(b, "  %-10s %s\n", "platform",
			padBetween(s.Platform, "duration "+fmtDur(s.Elapsed), reportWidth-13))
	}
	fmt.Fprintf(b, "  %-10s %d %s examined · %d discovered · %d hits · %d new %s\n",
		"scope", s.Examined, plural(s.Examined, "repo", "repos"),
		s.Discovered, s.Hits, s.Promoted, plural(s.Promoted, "IOC", "IOCs"))
	b.WriteString(rule + "\n")
}

// maxCandidates bounds the review-candidate list. Mining is deliberately
// generous (one earlier crawl queued 482 strings, nearly all JavaScript), so the
// report shows the most specific few and says how many more there were.
const maxCandidates = 20

// setIndicators adds what the hunt learned about indicators to the results.
func (r *results) setIndicators(promoted, candidates []indicator.Indicator) {
	for _, in := range promoted {
		r.Promoted = append(r.Promoted, toIOCEntry(in))
	}

	// Most specific first -- a URL or address is worth an analyst's glance long
	// before a bare string is -- then alphabetical, so the order is stable.
	sort.SliceStable(candidates, func(i, j int) bool {
		if ri, rj := kindRank(candidates[i].Kind), kindRank(candidates[j].Kind); ri != rj {
			return ri < rj
		}
		return candidates[i].Value < candidates[j].Value
	})
	if len(candidates) > maxCandidates {
		r.CandidatesMore = len(candidates) - maxCandidates
		candidates = candidates[:maxCandidates]
	}
	for _, in := range candidates {
		r.Candidates = append(r.Candidates, toIOCEntry(in))
	}
}

func kindRank(k indicator.Kind) int {
	switch k {
	case indicator.KindURL:
		return 0
	case indicator.KindIP:
		return 1
	case indicator.KindDomain:
		return 2
	case indicator.KindSecret:
		return 3
	}
	return 4
}

// toIOCEntry prepares an indicator for display. Everything here came out of a
// hostile file, so it is made safe first; then, because the report is meant to
// be read, pasted and opened, a URL is defanged (so no terminal or viewer turns
// a command-and-control address into a link) and a secret is masked (it may be
// a real credential that the operator stole).
func toIOCEntry(in indicator.Indicator) iocEntry {
	v := sanitize(in.Value)
	switch in.Kind {
	case indicator.KindURL:
		v = defangURL(v)
	case indicator.KindSecret:
		v = maskSecret(v)
	}
	return iocEntry{Kind: in.Kind.String(), Value: v, Source: truncate(sanitize(in.Source), 70)}
}

// defangURL breaks the scheme so the text is inert: https://x -> hxxps://x.
func defangURL(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "hxxps://" + u[len("https://"):]
	case strings.HasPrefix(u, "http://"):
		return "hxxp://" + u[len("http://"):]
	}
	return u
}

// maskSecret keeps enough to recognise a secret and nothing to use it.
func maskSecret(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "…(" + fmt.Sprint(len(r)) + " chars, masked)"
	}
	return string(r[:2]) + "…(" + fmt.Sprint(len(r)) + " chars, masked)"
}

// padBetween puts left and right on one line width columns wide, with the right
// text flush to the end; it falls back to a single space when they would
// collide. Widths are counted in runes so multi-byte characters stay aligned.
func padBetween(left, right string, width int) string {
	gap := width - len([]rune(left)) - len([]rune(right))
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// wrapIndent soft-wraps text to width columns, indenting every line after the
// first with indent. It keeps warnings from running off the side of the report.
func wrapIndent(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line + "\n" + indent)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// outputName is the deterministic, filesystem-safe result file name.
func outputName(t time.Time) string {
	return "skarvel_output_" + t.Format("20060102_150405") + ".txt"
}

// writeOutput creates the result file in the current directory without ever
// overwriting an existing one: two runs started in the same second get a
// numeric suffix instead.
func writeOutput(started time.Time, text string) (string, error) {
	base := strings.TrimSuffix(outputName(started), ".txt")
	for i := 0; i < 100; i++ {
		name := base + ".txt"
		if i > 0 {
			name = fmt.Sprintf("%s_%d.txt", base, i)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.WriteString(text); err != nil {
			f.Close()
			return "", err
		}
		return name, f.Close()
	}
	return "", errors.New("too many output files for the same second")
}
