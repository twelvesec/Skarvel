// Package criteria is tool.md section 4 and 7 in executable form: what counts
// as evidence, how much weight it carries, and what it licenses the crawler to
// do next.
//
// It exists as its own package because in an autonomous crawler the criteria do
// not merely label findings -- they steer the search. A weak criterion does not
// produce one bad row, it produces a bad subtree. Keeping the rules pure and
// separately testable is what lets that be verified without a network.
package criteria

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Tier is how much weight a signal carries on its own.
//
// The four tiers exist to separate two questions that a single severity scale
// conflated: how alarming a signal is, and whether it justifies spending the
// crawl budget on everything adjacent to it.
type Tier int

const (
	// TierNone is the absence of evidence.
	TierNone Tier = iota

	// TierD is a lead. It never scores and never incriminates.
	//
	// Identity-name matches live here alone. Impersonation targets are chosen
	// by the operator for their credibility, which makes the name a pointer to
	// where the operator has been -- and simultaneously makes the named person
	// a victim. Anything derived from a Tier-D match is labelled a lead.
	TierD

	// TierC supports a conclusion in combination but is common in isolation.
	// Records, never expands. Two distinct TierC signals in one file escalate.
	TierC

	// TierB is a mechanism that is very rarely legitimate. Records and expands.
	TierB

	// TierA matches known campaign infrastructure or proves impossibility.
	// One hit settles it.
	TierA
)

// Score is the contribution to a node's crawl priority.
//
// TierD is deliberately zero: a lead must not be able to push a node over the
// expansion threshold, however many leads accumulate.
func (t Tier) Score() int {
	switch t {
	case TierA:
		return 100
	case TierB:
		return 60
	case TierC:
		return 15
	default:
		return 0
	}
}

// Expands reports whether this tier alone licenses growing the frontier.
func (t Tier) Expands() bool { return t >= TierB }

func (t Tier) String() string {
	switch t {
	case TierA:
		return "A"
	case TierB:
		return "B"
	case TierC:
		return "C"
	case TierD:
		return "D"
	}
	return "-"
}

// ParseTier accepts both the tier letters and the names used by the older
// scanner, so existing signatures keep their meaning without being rewritten.
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "a", "definitive":
		return TierA, nil
	case "b", "strong":
		return TierB, nil
	case "c", "supporting":
		return TierC, nil
	case "d", "lead":
		return TierD, nil
	}
	return TierNone, fmt.Errorf("criteria: unknown tier %q", s)
}

// Subject is what a finding is evidence *about*.
//
// This is the field that enforces tool.md section 2: containment never implies
// authorship. A malicious file makes a statement about the file and about
// whoever committed it -- never about whoever happens to own the repository it
// sits in. Expansion reads this field, so the distinction is structural rather
// than a matter of care at each call site.
type Subject int

const (
	SubjectFile Subject = iota
	SubjectCommit
	SubjectIdentity
	SubjectRepo
	SubjectAccount
	SubjectIndicator
)

func (s Subject) String() string {
	switch s {
	case SubjectFile:
		return "file"
	case SubjectCommit:
		return "commit"
	case SubjectIdentity:
		return "identity"
	case SubjectRepo:
		return "repo"
	case SubjectAccount:
		return "account"
	case SubjectIndicator:
		return "indicator"
	}
	return "unknown"
}

// Finding is one piece of evidence, bound to what it is evidence about.
type Finding struct {
	Signal  string  // stable identifier, e.g. "remote-eval"
	Tier    Tier    //
	Subject Subject // what this is evidence about
	Why     string  // human-readable rationale

	Repo string // owner/name
	Path string // file path, when Subject is a file
	Line int    // 1-indexed, 0 when not line-anchored
	SHA  string // commit, when Subject is a commit or the introducing commit

	// Identity is the author identity implicated, when known. Populated for
	// file and commit findings so that expansion follows authorship.
	Identity string

	// Evidence is the matched text, truncated. Never the whole file.
	Evidence string

	// Documentary marks a match in a file that records rather than executes.
	// Such findings are kept in full but are barred from escalation: two
	// supporting signals in one prose file is still prose.
	Documentary bool

	// Host names the platform the repository lives on: "github" (the default
	// when empty) or "bitbucket". It only affects how permalinks are built.
	Host string
}

// Location renders "repo path:line" -- what a human needs to find the hit.
func (f Finding) Location() string {
	if f.Path == "" {
		return f.Repo
	}
	if f.Line > 0 {
		return f.Repo + " " + f.Path + ":" + strconv.Itoa(f.Line)
	}
	return f.Repo + " " + f.Path
}

// URL is a permanent link to the exact line on GitHub.
//
// Anchored to the commit SHA rather than a branch name: a branch moves, and the
// whole point of the link is that someone can still see what was found after
// the operator force-pushes over it or the repository is taken down and forked.
func (f Finding) URL() string {
	if f.Repo == "" {
		return ""
	}
	if f.Path == "" {
		return RepoURL(f.Host, f.Repo)
	}
	ref := f.SHA
	if ref == "" {
		ref = "HEAD"
	}
	if f.Host == HostBitbucket {
		u := "https://bitbucket.org/" + f.Repo + "/src/" + ref + "/" + f.Path
		if f.Line > 0 {
			u += "#lines-" + strconv.Itoa(f.Line)
		}
		return u
	}
	u := "https://github.com/" + f.Repo + "/blob/" + ref + "/" + f.Path
	if f.Line > 0 {
		u += "#L" + strconv.Itoa(f.Line)
	}
	return u
}

// Platform hosts a Finding can point at.
const (
	HostGitHub    = "github"
	HostBitbucket = "bitbucket"
)

// RepoURL returns the web page of a repository on the given host. An empty
// host means GitHub, which keeps every existing caller and report unchanged.
func RepoURL(host, repo string) string {
	if host == HostBitbucket {
		return "https://bitbucket.org/" + repo
	}
	return "https://github.com/" + repo
}

// CapDocumentaryTier lowers a finding matched in a file that records rather
// than executes.
//
// An indicator in `.vscode/settings.json` runs a shell. The same indicator in
// `README.md`, `iocs.csv` or a blog post does not: prose about malware is not
// malware. Both matches are true -- this is not false-positive suppression, and
// the finding is kept in full -- but only one of them is evidence that the
// repository is compromised.
//
// Without this, every security researcher who writes up the campaign and every
// blocklist that carries its domains is reported as MALICIOUS, which is both
// wrong and, published, defamatory.
func CapDocumentaryTier(f Finding, documentary bool) Finding {
	if !documentary {
		return f
	}
	// Mark first, cap second. An earlier version returned early for findings
	// already at TierC, so they were never marked -- and two of them in one
	// file still paired up into a strong signal, which is how a benchmark of
	// LLM explanations of malicious code came out MALICIOUS.
	f.Documentary = true
	if f.Tier <= TierC {
		return f
	}
	f.Tier = TierC
	f.Why += " — matched in a non-executing file, so this records the indicator rather than running it"
	return f
}

// Verdict is the repository-level conclusion.
type Verdict int

const (
	VerdictClean Verdict = iota
	VerdictReview
	VerdictMalicious
)

func (v Verdict) String() string {
	switch v {
	case VerdictMalicious:
		return "MALICIOUS"
	case VerdictReview:
		return "REVIEW"
	}
	return "CLEAN"
}

// Assessment is the composed result over a set of findings.
type Assessment struct {
	Verdict Verdict
	Score   int
	Reason  string

	// Expand reports whether the frontier may be grown from this node. It is
	// deliberately separate from Verdict: REVIEW records without expanding.
	Expand bool

	// Leads are the TierD findings, kept apart from the scored evidence so
	// they can never contribute to the verdict.
	Leads []Finding
}

// Assess composes findings into a verdict, per tool.md section 7:
//
//	MALICIOUS := any TierA | 2+ TierB | 1 TierB + 3 TierC in one file
//	REVIEW    := 1 TierB   | 2 TierC in one file
//
// The "in one file" qualifier is load-bearing. Supporting signals scattered
// across a repository are the normal texture of developer tooling; the same
// signals concentrated in a single file are what a payload looks like. An
// earlier repo-wide count of these produced ten false positives.
func Assess(findings []Finding) Assessment {
	var a Assessment
	var countA, countB int
	perFileC := map[string]map[string]bool{}
	perFileB := map[string]int{}

	for _, f := range findings {
		switch f.Tier {
		case TierD:
			a.Leads = append(a.Leads, f)
			continue // never scores
		case TierA:
			countA++
		case TierB:
			countB++
			perFileB[f.Path]++
		case TierC:
			// Documentary matches never pair up into a strong signal. Without
			// this the escalation rule turns two mentions in one results file
			// or blog post into MALICIOUS by the back door.
			if f.Documentary {
				break
			}
			if f.Path != "" {
				if perFileC[f.Path] == nil {
					perFileC[f.Path] = map[string]bool{}
				}
				perFileC[f.Path][f.Signal] = true
			}
		}
		a.Score += f.Tier.Score()
	}

	// Two distinct supporting signals in one file escalate to strong.
	escalated := 0
	maxC := 0
	var maxCPath string
	for path, sigs := range perFileC {
		if len(sigs) > maxC {
			maxC, maxCPath = len(sigs), path
		}
		if len(sigs) >= 2 {
			escalated++
		}
	}
	effectiveB := countB + escalated

	switch {
	case countA > 0:
		a.Verdict, a.Reason = VerdictMalicious, fmt.Sprintf("%d definitive signal(s)", countA)
	case effectiveB >= 2:
		a.Verdict = VerdictMalicious
		a.Reason = fmt.Sprintf("%d strong signal(s)", effectiveB)
		if escalated > 0 {
			a.Reason += fmt.Sprintf(" (%d escalated from paired supporting signals)", escalated)
		}
	case effectiveB == 1 && bestFileC(perFileC, perFileB) >= 3:
		a.Verdict = VerdictMalicious
		a.Reason = "1 strong signal with 3 supporting signals in the same file"
	case effectiveB == 1:
		a.Verdict, a.Reason = VerdictReview, "1 strong signal"
	case maxC >= 2:
		a.Verdict = VerdictReview
		a.Reason = fmt.Sprintf("%d supporting signals in %s", maxC, maxCPath)
	default:
		a.Verdict = VerdictClean
		if len(findings) > 0 {
			a.Reason = "no signal above the supporting threshold"
		} else {
			a.Reason = "no signals"
		}
	}

	// Expansion is licensed by evidence strength, not by the verdict. A REVIEW
	// records but must not spend budget on everything adjacent to it.
	a.Expand = countA > 0 || effectiveB >= 2 ||
		(effectiveB == 1 && bestFileC(perFileC, perFileB) >= 3)

	return a
}

// bestFileC returns the largest number of distinct supporting signals found in
// any single file that also carries a strong signal.
func bestFileC(perFileC map[string]map[string]bool, perFileB map[string]int) int {
	best := 0
	for path, sigs := range perFileC {
		if perFileB[path] == 0 {
			continue
		}
		if len(sigs) > best {
			best = len(sigs)
		}
	}
	return best
}

// ExpandTargets returns the node kinds that a finding licenses expanding to,
// enforcing tool.md section 2.
//
// Note what is absent: a file finding never yields the repository owner. It
// yields the commit that introduced it, and from there the author identity.
// Ownership is reached only when the owner turns out to be that author, which
// is a fact the crawler establishes rather than assumes.
func ExpandTargets(f Finding) []Subject {
	if !f.Tier.Expands() {
		return nil
	}
	switch f.Subject {
	case SubjectFile:
		return []Subject{SubjectCommit, SubjectIdentity}
	case SubjectCommit:
		return []Subject{SubjectIdentity}
	case SubjectIdentity:
		return []Subject{SubjectRepo}
	case SubjectRepo:
		return []Subject{SubjectCommit}
	case SubjectAccount:
		return []Subject{SubjectRepo}
	case SubjectIndicator:
		return []Subject{SubjectRepo}
	}
	return nil
}

// SortFindings orders findings strongest-first for display and reporting.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Tier != fs[j].Tier {
			return fs[i].Tier > fs[j].Tier
		}
		if fs[i].Repo != fs[j].Repo {
			return fs[i].Repo < fs[j].Repo
		}
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		return fs[i].Line < fs[j].Line
	})
}
