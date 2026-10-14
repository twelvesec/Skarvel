package guard

import (
	"regexp"
	"strings"
)

// A repository can carry the campaign's files and still be on the defenders'
// side: researchers and victims publish copies of a lure precisely so others can
// study it, and say so at the top of the README ("THIS REPO CONTAINS MALICIOUS
// CODE ... DO NOT DOWNLOAD OR RUN THIS CODE"). Such a repository matches every
// signature the tool has, so without this check it is reported as a confirmed
// operator asset.
//
// The notice is the owner's claim and nothing more -- an operator can write the
// same sentence to hide a real lure -- so it never silences a repository. It
// moves it to its own report section, with the quoted sentence and the files
// that matched, and keeps it out of the MALICIOUS count.

var (
	// warnClaim: the text says the repository holds something harmful.
	warnClaim = regexp.MustCompile(
		`malicio\w*|malware|trojan|backdoor|ransomware|infostealer|` +
			`attack\s+your\s+(?:machine|computer|system|pc|device)|` +
			`compromis\w+\s+your\s+(?:machine|computer|system|pc|device)`)

	// warnAdvice: the text tells the reader not to use the repository, or says it
	// exists for study only.
	warnAdvice = regexp.MustCompile(
		`\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:\w+\s+){0,3}?` +
			`(?:download|clone|run|execute|open|install|fork|pull|use|visit)\b|` +
			`\bfor\s+(?:\w+\s+){0,2}?` +
			`(?:investigation|investigative|investigating|research|analysis|educational|awareness|warning|reference|documentation)\s+` +
			`(?:purposes?\s+)?only\b`)
)

// warnWindow is how close, in bytes of normalised text, the claim and the advice
// must be. A security library that says "rejects malicious input" in one
// paragraph and "do not run as root" in another is not warning about itself.
const warnWindow = 400

// warnHead bounds how much of the README is read. A notice that matters is put
// at the top; one buried in the tail is usually ordinary documentation.
const warnHead = 3000

// Warning is a repository's own notice that it holds malicious material.
type Warning struct {
	Found bool
	Quote string // the sentence(s) that matched, whitespace-normalised and short
}

// DetectWarning reports whether the description or the head of the README says,
// in the owner's words, that the repository contains malicious code and must not
// be run or downloaded (or exists for investigation only).
func DetectWarning(description, readmeHead string) Warning {
	text := description + "\n" + readmeHead
	if len(text) > warnHead {
		text = text[:warnHead]
	}
	text = strings.Join(strings.Fields(text), " ")
	low := strings.ToLower(text)

	claims := warnClaim.FindAllStringIndex(low, -1)
	advice := warnAdvice.FindAllStringIndex(low, -1)
	for _, c := range claims {
		for _, a := range advice {
			if abs(c[0]-a[0]) > warnWindow {
				continue
			}
			lo, hi := min(c[0], a[0]), max(c[1], a[1])
			return Warning{Found: true, Quote: quote(text, lo, hi)}
		}
	}
	return Warning{}
}

// quote returns the text covering [lo,hi) widened a little and cut to a safe
// length. The bytes come from an untrusted README, so callers must still pass
// them through the report's sanitiser.
func quote(text string, lo, hi int) string {
	const pad, maxLen = 20, 220
	lo = clampInt(lo-pad, 0, len(text))
	hi = clampInt(hi+pad, 0, len(text))
	q := strings.ToValidUTF8(text[lo:hi], "")
	if len(q) > maxLen {
		q = q[:maxLen]
		q = strings.ToValidUTF8(q, "") + "…"
	}
	return strings.TrimSpace(q)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func clampInt(n, lo, hi int) int { return min(max(n, lo), hi) }
