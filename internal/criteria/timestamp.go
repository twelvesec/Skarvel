package criteria

import (
	"math"
	"strings"
)

// OnTheHourProb is the chance an organic commit lands on an exact hour by
// coincidence: one second in 3600.
const OnTheHourProb = 1.0 / 3600.0

// Thresholds for the forged-history test, per tool.md section 6.
//
// These are tuned to prefer specificity. A p-value alone is not enough: five
// on-the-hour commits out of twenty already yields p ~= 2.6e-14, which would
// flag trivially seeded repositories and, worse, expand into them. The count
// floor is what implements "rather miss small seeded repositories".
const (
	ForgedMinCountStrong = 10
	// Expressed as log10 because the p-values in this regime reach 1e-2000,
	// which is not representable as a float64 -- see BinomialUpperTailLog10.
	ForgedMaxLog10PStrong = -9
	ForgedMinCommits      = 20

	ForgedMinCountSupport  = 3
	ForgedMaxLog10PSupport = -6
)

// ClockSample is one commit reduced to what the test needs.
type ClockSample struct {
	SHA string
	// Hour, Min, Sec are the author's LOCAL wall clock, including their own UTC
	// offset. Local, not UTC: a generator stamps a fixed local hour while the
	// UTC instant varies per persona timezone, so the pattern is invisible in
	// UTC once more than one timezone is involved.
	Hour, Min, Sec int
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	Valid          bool
}

// OnTheHour reports whether this commit sits exactly on an hour boundary.
func (c ClockSample) OnTheHour() bool { return c.Valid && c.Min == 0 && c.Sec == 0 }

// TimestampResult is the outcome of the forged-history test.
type TimestampResult struct {
	Considered int // commits after bot exclusion
	Excluded   int // commits dropped as automation
	OnHour     int // k
	// Log10P is log10 of the upper-tail probability. A fabricated history of a
	// few hundred commits produces a tail far below the smallest float64, so
	// the exponent is carried rather than the value.
	Log10P float64
	Tier   Tier

	// DominantHour and DominantCount name the most common on-the-hour value.
	// The campaign that motivated this used 12:00:00 local; the test is general
	// but the specific hour is worth reporting.
	DominantHour  int
	DominantCount int
}

// botMarkers identify automation that legitimately commits on the hour.
//
// Without this exclusion the test flags a large fraction of actively maintained
// repositories: scheduled jobs, release automation and dependency bots all
// commit at exact times by design. They are removed before the test rather than
// discounted after it, so they cannot influence the denominator either.
var botMarkers = []string{
	"[bot]",
	"dependabot",
	"renovate",
	"github-actions",
	"greenkeeper",
	"snyk-bot",
	"semantic-release",
	"allcontributors",
	"imgbot",
	"pre-commit-ci",
	"noreply@github.com/apps/",
}

// IsBot reports whether an identity is automation.
func IsBot(name, email string) bool {
	s := strings.ToLower(name + " " + email)
	for _, m := range botMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// AnalyseTimestamps runs the forged-history test over a repository's commits.
//
// It returns TierB when the clustering is strong enough to justify spending
// crawl budget on the repository, TierC when it is worth recording only, and
// TierNone otherwise.
func AnalyseTimestamps(samples []ClockSample) TimestampResult {
	var r TimestampResult
	byHour := map[int]int{}

	for _, s := range samples {
		if !s.Valid {
			continue
		}
		if IsBot(s.AuthorName, s.AuthorEmail) || IsBot(s.CommitterName, s.CommitterEmail) {
			r.Excluded++
			continue
		}
		r.Considered++
		if s.OnTheHour() {
			r.OnHour++
			byHour[s.Hour]++
		}
	}
	for h, n := range byHour {
		if n > r.DominantCount || (n == r.DominantCount && h < r.DominantHour) {
			r.DominantHour, r.DominantCount = h, n
		}
	}

	r.Log10P = BinomialUpperTailLog10(r.Considered, r.OnHour, OnTheHourProb)

	switch {
	case r.OnHour >= ForgedMinCountStrong && r.Log10P < ForgedMaxLog10PStrong && r.Considered >= ForgedMinCommits:
		r.Tier = TierB
	case r.OnHour >= ForgedMinCountSupport && r.Log10P < ForgedMaxLog10PSupport:
		r.Tier = TierC
	default:
		r.Tier = TierNone
	}
	return r
}

// BinomialUpperTailLog10 returns log10 P(X >= k) for X ~ Binomial(n, p).
//
// It returns the exponent rather than the probability because the tails this
// test produces are genuinely unrepresentable: 400 on-the-hour commits out of
// 800 gives a tail near 1e-1100, which is zero in float64. Returning zero would
// read as "impossible" -- indistinguishable from an arithmetic failure -- so
// the whole computation stays in log space and never exponentiates the result.
func BinomialUpperTailLog10(n, k int, p float64) float64 {
	if k <= 0 {
		return 0 // log10(1)
	}
	if n <= 0 || k > n {
		return math.Inf(-1)
	}

	logP := math.Log(p)
	logQ := math.Log1p(-p)

	// Collect log terms, tracking the maximum for a stable log-sum-exp. In
	// this test k is far above the mean n*p, so the first term dominates and
	// the rest decay quickly; the loop stops once they cannot contribute.
	maxLog := math.Inf(-1)
	logs := make([]float64, 0, 64)
	for i := k; i <= n; i++ {
		lt := lchoose(n, i) + float64(i)*logP + float64(n-i)*logQ
		if math.IsInf(lt, -1) || math.IsNaN(lt) {
			break
		}
		logs = append(logs, lt)
		if lt > maxLog {
			maxLog = lt
		} else if lt < maxLog-50 {
			break // contributes less than 1e-21 of the running total
		}
	}
	if math.IsInf(maxLog, -1) || len(logs) == 0 {
		return math.Inf(-1)
	}

	sum := 0.0
	for _, lt := range logs {
		sum += math.Exp(lt - maxLog)
	}
	return (maxLog + math.Log(sum)) / math.Ln10
}

// lchoose is log(C(n, k)) via log-gamma, which stays finite where the direct
// factorial overflows.
func lchoose(n, k int) float64 {
	lg1, _ := math.Lgamma(float64(n) + 1)
	lg2, _ := math.Lgamma(float64(k) + 1)
	lg3, _ := math.Lgamma(float64(n-k) + 1)
	return lg1 - lg2 - lg3
}

// ToFinding converts a timestamp result into a repository-level finding.
func (r TimestampResult) ToFinding(repo string) (Finding, bool) {
	if r.Tier == TierNone {
		return Finding{}, false
	}
	why := "commit history clusters on exact hour boundaries beyond coincidence"
	if r.DominantCount > 0 {
		why += ", predominantly " + itoa2(r.DominantHour) + ":00:00 local"
	}
	return Finding{
		Signal:  "forged-timestamps",
		Tier:    r.Tier,
		Subject: SubjectRepo,
		Repo:    repo,
		Why:     why,
		Evidence: itoa(r.OnHour) + " of " + itoa(r.Considered) +
			" commits on the hour (p=" + fmtLog10P(r.Log10P) + ", " + itoa(r.Excluded) + " bot commits excluded)",
	}, true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func itoa2(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

func fmtLog10P(l float64) string {
	if math.IsInf(l, -1) {
		return "0"
	}
	e := int(math.Floor(l))
	m := math.Pow(10, l-float64(e))
	return trimF(m) + "e" + itoa(e)
}

func trimF(f float64) string {
	s := math.Round(f*10) / 10
	i := int(s)
	frac := int(math.Round((s - float64(i)) * 10))
	if frac == 0 {
		return itoa(i)
	}
	return itoa(i) + "." + itoa(frac)
}

// PersonaMinCommits is the smallest history a single author needs before
// "every one of their commits is on the hour" is treated as a fingerprint
// rather than coincidence. Carried over unchanged from the scan command.
const PersonaMinCommits = 3

// Persona is one author identity whose every commit sits on an exact local
// hour -- the per-author view of a generated history.
type Persona struct {
	Name, Email string
	Commits     int
	Hour        int // the local hour most of their commits are stamped with
}

// ForgedPersonas finds author identities whose entire history in a repository
// is stamped on the hour.
//
// The repository-level test (AnalyseTimestamps) can be diluted by organic
// commits from real contributors; a fabricated persona inside an otherwise
// genuine history still shows up here. This is how additional personas were
// found without knowing to look for them. Bots are excluded first, exactly as
// in the repository-level test.
func ForgedPersonas(samples []ClockSample) []Persona {
	type acc struct {
		Persona
		onHour int
		hours  map[int]int
	}
	by := map[string]*acc{}
	var order []string
	for _, s := range samples {
		if !s.Valid || IsBot(s.AuthorName, s.AuthorEmail) || IsBot(s.CommitterName, s.CommitterEmail) {
			continue
		}
		k := strings.ToLower(s.AuthorName + "\x00" + s.AuthorEmail)
		a, ok := by[k]
		if !ok {
			a = &acc{Persona: Persona{Name: s.AuthorName, Email: s.AuthorEmail}, hours: map[int]int{}}
			by[k] = a
			order = append(order, k)
		}
		a.Commits++
		if s.OnTheHour() {
			a.onHour++
			a.hours[s.Hour]++
		}
	}
	var out []Persona
	for _, k := range order {
		a := by[k]
		if a.Commits < PersonaMinCommits || a.onHour != a.Commits {
			continue
		}
		best := -1
		for h, n := range a.hours {
			if best < 0 || n > a.hours[best] || (n == a.hours[best] && h < best) {
				best = h
			}
		}
		a.Hour = best
		out = append(out, a.Persona)
	}
	return out
}

// ToFinding records a forged persona as supporting evidence about the
// repository. It is TierC on purpose: it records and never expands, and it
// names a person, who in this campaign was an impersonation target.
func (p Persona) ToFinding(repo string) Finding {
	return Finding{
		Signal:   "forged-persona",
		Tier:     TierC,
		Subject:  SubjectIdentity,
		Repo:     repo,
		Identity: p.Name + " <" + p.Email + ">",
		Why: "every commit by this author identity is stamped exactly " + itoa2(p.Hour) +
			":00:00 local; the identity is more likely impersonated than responsible",
		Evidence: itoa(p.Commits) + " of " + itoa(p.Commits) + " commits on the hour",
	}
}
