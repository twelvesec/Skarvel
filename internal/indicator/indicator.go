// Package indicator handles the flywheel: matching known campaign strings in
// source, mining new ones from confirmed-malicious files, and gating which of
// those are allowed to become search seeds.
//
// The gate is the important part. Auto-promoting a generic string turns a
// targeted hunt into a crawl of all of GitHub, so only network locators and
// high-entropy secrets extracted from already-confirmed files are promoted
// automatically; everything else is queued for a human (tool.md section 10).
package indicator

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"strconv"
	"strings"

	"skarvel/internal/criteria"
)

// Kind classifies an indicator by how specific it is.
type Kind int

const (
	KindGeneric Kind = iota
	KindDomain
	KindIP
	KindURL
	KindSecret
)

func (k Kind) String() string {
	switch k {
	case KindDomain:
		return "domain"
	case KindIP:
		return "ip"
	case KindURL:
		return "url"
	case KindSecret:
		return "secret"
	}
	return "generic"
}

// AutoPromotable reports whether this kind may become a search seed without
// review. Generic strings never qualify.
func (k Kind) AutoPromotable() bool {
	return k == KindDomain || k == KindIP || k == KindURL || k == KindSecret
}

// Indicator is one campaign string.
type Indicator struct {
	Value     string
	Kind      Kind
	Source    string // "seed", or "repo:path" it was mined from
	Confirmed bool   // extracted from a file already assessed Tier A
}

// campaignAlphabet is the non-standard base64 alphabet used by this family's
// obfuscator: lowercase first, where the standard alphabet is uppercase first.
// A payload encoded with it is invisible to a standard base64 decode.
// The trailing "=" is the padding character, which NewEncoding takes
// separately -- the alphabet proper is the first 64 symbols.
const campaignAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

var campaignB64 = base64.NewEncoding(campaignAlphabet).WithPadding('=')

// Variants returns the encoded forms an indicator may appear as.
//
// Matching only the raw form produces false negatives on this family, which
// hides endpoints as base64 and as hex escapes.
func Variants(v string) []string {
	if v == "" {
		return nil
	}
	out := []string{v}
	add := func(s string) {
		if s == "" || s == v {
			return
		}
		for _, e := range out {
			if e == s {
				return
			}
		}
		out = append(out, s)
	}

	add(base64.StdEncoding.EncodeToString([]byte(v)))
	add(strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(v)), "="))
	add(campaignB64.EncodeToString([]byte(v)))
	add(strings.TrimRight(campaignB64.EncodeToString([]byte(v)), "="))
	add(hex.EncodeToString([]byte(v)))

	var esc strings.Builder
	for _, b := range []byte(v) {
		esc.WriteString("\\x" + hex.EncodeToString([]byte{b}))
	}
	add(esc.String())

	return out
}

var (
	reStrConcat = regexp.MustCompile(`(["'])\s*\+\s*(["'])`)
	reHexEsc    = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reCharCode  = regexp.MustCompile(`String\.fromCharCode\(([0-9,\s]+)\)`)
)

// normalise produces the searchable forms of a chunk of source.
//
// Joining adjacent string literals is not optional. Searching unjoined output
// once produced a confident wrong conclusion that wallet targeting was absent
// from a payload; the strings were there, split across `" + "` boundaries.
func normalise(s string) []string {
	out := []string{s}

	if joined := reStrConcat.ReplaceAllString(s, ""); joined != s {
		out = append(out, joined)
	}
	if un := reHexEsc.ReplaceAllStringFunc(s, func(m string) string {
		b, err := strconv.ParseUint(m[2:], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(b))
	}); un != s {
		out = append(out, un)
	}
	if cc := reCharCode.ReplaceAllStringFunc(s, func(m string) string {
		inner := m[strings.Index(m, "(")+1 : len(m)-1]
		var b strings.Builder
		for _, part := range strings.Split(inner, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return m
			}
			b.WriteRune(rune(n))
		}
		return b.String()
	}); cc != s {
		out = append(out, cc)
	}
	return out
}

// logicalLine is a source line, joined with its continuations so that a string
// split across several physical lines is still searchable, while keeping the
// line number of where it started.
type logicalLine struct {
	text string
	line int
}

// Joining is bounded because the input is attacker-controlled. A file made of
// thousands of lines that each begin with `+` (a patch pasted into a .txt or
// .md) would otherwise fold into one line, and re-copying that growing string
// on every join is quadratic: one such file could stall a whole run. A real
// string concatenation spans a handful of lines, so the limits cost nothing.
const (
	maxJoinedBytes = 64 << 10 // longest joined logical line
	maxJoinedParts = 256      // most physical lines folded into one
)

// continues reports whether a line ending in cur carries on into next: a line
// ending in `+`, or whose successor begins with `+`, is a concatenation
// continued across lines.
func continues(cur, next string) bool {
	return strings.HasSuffix(cur, "+") || strings.HasPrefix(next, "+")
}

func logicalLines(content string) []logicalLine {
	raw := strings.Split(content, "\n")
	var out []logicalLine
	for i := 0; i < len(raw); i++ {
		text := raw[i]
		start := i + 1
		if first := strings.TrimRight(text, " \t\r"); i+1 < len(raw) && continues(first, strings.TrimSpace(raw[i+1])) {
			// The builder's contents are always right-trimmed, so they stand in
			// for the trimmed text of the previous iteration.
			var b strings.Builder
			b.WriteString(first)
			for parts := 0; i+1 < len(raw) && parts < maxJoinedParts && b.Len() < maxJoinedBytes; parts++ {
				next := strings.TrimSpace(raw[i+1])
				if !continues(b.String(), next) {
					break
				}
				b.WriteString(next)
				i++
			}
			text = b.String()
		}
		out = append(out, logicalLine{text: text, line: start})
	}
	return out
}

// Set is the active indicator list.
type Set struct {
	inds     []Indicator
	variants map[string][]string // indicator value -> encoded forms
}

func NewSet(inds ...Indicator) *Set {
	s := &Set{variants: map[string][]string{}}
	for _, in := range inds {
		s.Add(in)
	}
	return s
}

func (s *Set) Add(in Indicator) {
	if in.Value == "" {
		return
	}
	for _, e := range s.inds {
		if e.Value == in.Value {
			return
		}
	}
	s.inds = append(s.inds, in)
	s.variants[in.Value] = Variants(in.Value)
}

// Has reports whether value is already in the set (ignoring case).
func (s *Set) Has(value string) bool {
	for _, e := range s.inds {
		if strings.EqualFold(e.Value, value) {
			return true
		}
	}
	return false
}

func (s *Set) All() []Indicator { return append([]Indicator(nil), s.inds...) }
func (s *Set) Len() int         { return len(s.inds) }

// Match searches content for every indicator in every encoding.
//
// A hit on a confirmed indicator is Tier A: these are known campaign
// infrastructure, and one occurrence settles the question.
func (s *Set) Match(repo, path string, content []byte) []criteria.Finding {
	var out []criteria.Finding
	seen := map[string]bool{}

	for _, ll := range logicalLines(string(content)) {
		forms := normalise(ll.text)
		lower := make([]string, len(forms))
		for i, f := range forms {
			lower[i] = strings.ToLower(f)
		}

		for _, in := range s.inds {
			for _, v := range s.variants[in.Value] {
				needle := strings.ToLower(v)
				hit := false
				for _, h := range lower {
					if strings.Contains(h, needle) {
						hit = true
						break
					}
				}
				if !hit {
					continue
				}
				key := in.Value + "\x00" + strconv.Itoa(ll.line)
				if seen[key] {
					break
				}
				seen[key] = true

				tier := criteria.TierA
				if !in.Confirmed {
					tier = criteria.TierB
				}
				out = append(out, criteria.Finding{
					Signal:   "indicator-" + in.Kind.String(),
					Tier:     tier,
					Subject:  criteria.SubjectFile,
					Repo:     repo,
					Path:     path,
					Line:     ll.line,
					Why:      "matches known campaign indicator " + strconv.Quote(in.Value),
					Evidence: truncate(strings.TrimSpace(ll.text), 160),
				})
				break
			}
		}
	}
	return out
}

var (
	reURL    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
	reIPPort = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?\b`)
	reDomain = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
	reB64    = regexp.MustCompile(`\b[A-Za-z0-9+/]{16,}={0,2}\b`)
	reSecret = regexp.MustCompile(`\b[A-Za-z0-9!@#$%^&*()_+=~-]{16,80}\b`)
)

// knownTLDs is what separates a hostname from a property access.
//
// Without it the miner reported `console.log`, `editor.fontSize`, `cmd.exe`,
// `module.exports` and `process.env` as candidate domains -- 482 queued
// candidates from one crawl, almost all of them JavaScript syntax. The
// promotion gate held (nothing reached the search seeds), but a review queue
// nobody can read is a review queue nobody uses.
var knownTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "co": true, "dev": true,
	"app": true, "pro": true, "info": true, "biz": true, "me": true, "tv": true,
	"cc": true, "ai": true, "xyz": true, "site": true, "online": true, "top": true,
	"cloud": true, "tech": true, "digital": true, "space": true, "live": true,
	"life": true, "world": true, "today": true, "news": true, "zone": true,
	"link": true, "click": true, "win": true, "vip": true, "icu": true, "fun": true,
	"store": true, "shop": true, "blog": true, "wiki": true, "host": true,
	"press": true, "agency": true, "solutions": true, "services": true,
	"network": true, "systems": true, "group": true, "team": true, "works": true,
	"gg": true, "sh": true, "to": true, "ly": true, "im": true, "is": true,
	"it": true, "in": true, "id": true, "fr": true, "de": true, "uk": true,
	"ru": true, "cn": true, "jp": true, "kr": true, "br": true, "au": true,
	"ca": true, "nl": true, "se": true, "no": true, "fi": true, "dk": true,
	"pl": true, "es": true, "pt": true, "ch": true, "at": true, "be": true,
	"cz": true, "gr": true, "hu": true, "ro": true, "bg": true, "ua": true,
	"za": true, "mx": true, "ar": true, "cl": true, "pe": true, "nz": true,
	"sg": true, "hk": true, "tw": true, "th": true, "vn": true, "my": true,
	"ph": true, "tr": true, "il": true, "ae": true, "sa": true, "ng": true,
	"ke": true, "eu": true, "us": true, "gov": true, "edu": true, "mil": true,
	"int": true, "asia": true, "mobi": true, "name": true, "cat": true,
}

// hasKnownTLD reports whether a dotted string ends in a real top-level domain.
func hasKnownTLD(host string) bool {
	i := strings.LastIndex(host, ".")
	if i < 0 {
		return false
	}
	return knownTLDs[strings.ToLower(host[i+1:])]
}

// benignHosts are hosts common enough that promoting one as a campaign
// indicator would send the crawl over most of GitHub.
var benignHosts = map[string]bool{
	"github.com": true, "api.github.com": true, "raw.githubusercontent.com": true,
	"gist.github.com": true, "codeload.github.com": true, "objects.githubusercontent.com": true,
	"npmjs.com": true, "www.npmjs.com": true, "registry.npmjs.org": true, "npmjs.org": true,
	"nodejs.org": true, "yarnpkg.com": true, "unpkg.com": true, "jsdelivr.net": true,
	"cdn.jsdelivr.net": true, "googleapis.com": true, "www.googleapis.com": true,
	"fonts.googleapis.com": true, "gstatic.com": true, "cloudflare.com": true,
	"schema.org": true, "www.w3.org": true, "w3.org": true, "example.com": true,
	"localhost": true, "microsoft.com": true, "visualstudio.com": true,
	"golang.org": true, "pkg.go.dev": true, "proxy.golang.org": true,
	"python.org": true, "pypi.org": true, "docker.com": true, "hub.docker.com": true,
	"apache.org": true, "mozilla.org": true, "stackoverflow.com": true,
	"opensource.org": true, "creativecommons.org": true, "ietf.org": true,
	// Appears in this family's own payloads (`npm install socket.io-client`)
	// and in ordinary code alike; never a campaign indicator.
	"socket.io": true, "chai.io": true, "expressjs.com": true, "reactjs.org": true,
	"vitejs.dev": true, "webpack.js.org": true, "eslint.org": true,
}

// privateOrDocIP reports addresses that carry no campaign information.
func privateOrDocIP(ip string) bool {
	switch {
	case strings.HasPrefix(ip, "127."), strings.HasPrefix(ip, "10."),
		strings.HasPrefix(ip, "192.168."), strings.HasPrefix(ip, "169.254."),
		strings.HasPrefix(ip, "0."), strings.HasPrefix(ip, "255."),
		ip == "8.8.8.8", ip == "1.1.1.1":
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) > 1 {
			if n, err := strconv.Atoi(parts[1]); err == nil && n >= 16 && n <= 31 {
				return true
			}
		}
	}
	return false
}

// Extract mines candidate indicators out of a file.
//
// Candidates are not indicators yet: Promote decides that. The split matters
// because extraction is deliberately generous and promotion is deliberately
// strict.
func Extract(repo, path string, content []byte) []Indicator {
	src := string(content)
	// Search the decoded forms too, so a base64-wrapped endpoint is found.
	haystacks := normalise(src)
	for _, m := range reB64.FindAllString(src, -1) {
		if dec, err := base64.StdEncoding.DecodeString(pad(m)); err == nil && printable(dec) {
			haystacks = append(haystacks, string(dec))
		}
		if dec, err := campaignB64.DecodeString(pad(m)); err == nil && printable(dec) {
			haystacks = append(haystacks, string(dec))
		}
	}

	seen := map[string]bool{}
	var out []Indicator
	add := func(v string, k Kind) {
		v = strings.TrimRight(strings.TrimSpace(v), "/.,;:'\")")
		if v == "" || seen[v] || isJunk(v, k) {
			return
		}
		seen[v] = true
		out = append(out, Indicator{Value: v, Kind: k, Source: repo + ":" + path})
	}

	for _, h := range haystacks {
		for _, u := range reURL.FindAllString(h, -1) {
			if host := hostOf(u); host != "" && !benignHosts[strings.ToLower(host)] {
				add(u, KindURL)
			}
		}
		for _, m := range reIPPort.FindAllStringSubmatch(h, -1) {
			if !privateOrDocIP(m[1]) && validIP(m[1]) {
				add(m[0], KindIP)
			}
		}
		for _, d := range reDomain.FindAllString(h, -1) {
			ld := strings.ToLower(d)
			if hasKnownTLD(ld) && !benignHosts[ld] {
				add(d, KindDomain)
			}
		}
		for _, c := range reSecret.FindAllString(h, -1) {
			if Entropy(c) >= 4.0 && hasMixedClasses(c) {
				add(c, KindSecret)
			}
		}
	}
	return out
}

// Promote applies the gate of tool.md section 10.
//
// auto means the indicator becomes a search seed immediately; queued means it
// is held for review. Anything mined from a file that is not itself confirmed
// is queued regardless of how specific it looks, because otherwise a single
// misclassified file seeds the crawl with a legitimate domain.
func Promote(cand Indicator, fromConfirmedFile bool) (auto, queued bool) {
	if !fromConfirmedFile {
		return false, true
	}
	if !cand.Kind.AutoPromotable() {
		return false, true
	}
	if host := hostOf(cand.Value); host != "" && benignHosts[strings.ToLower(host)] {
		return false, false // never, not even for review
	}
	if benignHosts[strings.ToLower(cand.Value)] {
		return false, false
	}
	if cand.Kind == KindDomain && !hasKnownTLD(cand.Value) {
		return false, false // a property access, not a host
	}
	if len(cand.Value) < 8 {
		return false, true
	}
	return true, false
}

// Entropy is Shannon entropy in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		e -= p * math.Log2(p)
	}
	return e
}

func hasMixedClasses(s string) bool {
	var lower, upper, digit bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit} {
		if b {
			n++
		}
	}
	return n >= 2
}

func hostOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if j := strings.IndexAny(rest, "/:?#"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func validIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func pad(s string) string {
	if m := len(s) % 4; m != 0 {
		return s + strings.Repeat("=", 4-m)
	}
	return s
}

func printable(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	n := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			n++
		}
	}
	return float64(n)/float64(len(b)) > 0.9
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var (
	reWholeB64 = regexp.MustCompile(`^[A-Za-z0-9+/_-]{8,}={0,2}$`)
	reWholeHex = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){6,}$`)
)

// Decode returns the plain-text forms an encoded IOC stands for.
//
// Variants goes from a plain indicator to its encodings; this is the reverse,
// for an analyst who pastes the encoded form straight out of a payload. Only a
// decode that yields entirely printable text is kept, so an ordinary word that
// happens to be valid base64 does not seed the crawl with binary noise.
func Decode(v string) []string {
	v = strings.TrimSpace(v)
	var out []string
	add := func(b []byte) {
		s := strings.TrimSpace(string(b))
		if len(s) < 6 || s == v || !strictPrintable(s) {
			return
		}
		for _, e := range out {
			if e == s {
				return
			}
		}
		out = append(out, s)
	}
	if reWholeB64.MatchString(v) {
		raw := strings.TrimRight(v, "=")
		for _, enc := range []*base64.Encoding{
			base64.RawStdEncoding, base64.RawURLEncoding, campaignB64.WithPadding(base64.NoPadding),
		} {
			if b, err := enc.DecodeString(raw); err == nil {
				add(b)
			}
		}
	}
	if reWholeHex.MatchString(v) {
		if b, err := hex.DecodeString(v); err == nil {
			add(b)
		}
	}
	return out
}

func strictPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}
