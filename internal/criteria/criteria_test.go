package criteria

import (
	"math"
	"math/rand"
	"testing"
)

func f(sig string, tier Tier, path string) Finding {
	return Finding{Signal: sig, Tier: tier, Subject: SubjectFile, Path: path}
}

func TestAssessComposition(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     Verdict
		expand   bool
	}{
		{"nothing", nil, VerdictClean, false},
		{"single definitive", []Finding{f("ioc-domain", TierA, "a.js")}, VerdictMalicious, true},
		{"single strong", []Finding{f("remote-eval", TierB, "a.js")}, VerdictReview, false},
		{"two strong", []Finding{
			f("remote-eval", TierB, "a.js"),
			f("vscode-autorun", TierB, "b.json"),
		}, VerdictMalicious, true},
		{
			// The regression that produced ten false positives: a lone
			// supporting signal on developer tooling must not escalate.
			name:     "lone supporting",
			findings: []Finding{f("curl-pipe-shell", TierC, "install.sh")},
			want:     VerdictClean,
			expand:   false,
		},
		{
			name: "two distinct supporting in one file escalate to strong",
			findings: []Finding{
				f("curl-pipe-shell", TierC, "x.sh"),
				f("hidden-window-exec", TierC, "x.sh"),
			},
			want:   VerdictReview,
			expand: false,
		},
		{
			// Same signal twice is one signal, not a pair.
			name: "duplicate supporting signal does not escalate",
			findings: []Finding{
				f("curl-pipe-shell", TierC, "x.sh"),
				f("curl-pipe-shell", TierC, "x.sh"),
			},
			want:   VerdictClean,
			expand: false,
		},
		{
			// Scattered across files is the texture of normal tooling.
			name: "supporting signals in different files do not escalate",
			findings: []Finding{
				f("curl-pipe-shell", TierC, "a.sh"),
				f("hidden-window-exec", TierC, "b.ps1"),
			},
			want:   VerdictClean,
			expand: false,
		},
		{
			name: "four distinct supporting in one file reach malicious via escalation pairs",
			findings: []Finding{
				f("s1", TierC, "x.js"), f("s2", TierC, "x.js"),
				f("s3", TierC, "y.js"), f("s4", TierC, "y.js"),
			},
			want:   VerdictMalicious,
			expand: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Assess(c.findings)
			if got.Verdict != c.want {
				t.Errorf("verdict = %v, want %v (reason %q)", got.Verdict, c.want, got.Reason)
			}
			if got.Expand != c.expand {
				t.Errorf("expand = %v, want %v", got.Expand, c.expand)
			}
		})
	}
}

// A lead must never be able to reach a verdict, however many accumulate.
func TestTierDNeverScores(t *testing.T) {
	var fs []Finding
	for i := 0; i < 50; i++ {
		fs = append(fs, Finding{Signal: "identity-name", Tier: TierD, Subject: SubjectIdentity})
	}
	a := Assess(fs)
	if a.Verdict != VerdictClean {
		t.Errorf("verdict = %v, want CLEAN", a.Verdict)
	}
	if a.Score != 0 {
		t.Errorf("score = %d, want 0", a.Score)
	}
	if a.Expand {
		t.Error("leads must not expand the frontier")
	}
	if len(a.Leads) != 50 {
		t.Errorf("leads = %d, want 50 recorded separately", len(a.Leads))
	}
}

// Containment must never imply authorship: a file finding may not reach the
// repository owner directly.
func TestExpandTargetsNeverReachesOwnerFromFile(t *testing.T) {
	got := ExpandTargets(Finding{Tier: TierA, Subject: SubjectFile})
	for _, s := range got {
		if s == SubjectAccount {
			t.Fatal("a file finding must not expand to an account; " +
				"the repo owner may be a victim of the push")
		}
	}
	if len(got) == 0 {
		t.Fatal("a definitive file finding should expand to commit and identity")
	}
}

func TestExpandTargetsRequiresExpandingTier(t *testing.T) {
	for _, tier := range []Tier{TierC, TierD, TierNone} {
		if got := ExpandTargets(Finding{Tier: tier, Subject: SubjectFile}); got != nil {
			t.Errorf("tier %v expanded to %v, want none", tier, got)
		}
	}
}

func TestBinomialUpperTailLog10(t *testing.T) {
	// P(X >= 0) is the whole distribution: log10(1) == 0.
	if got := BinomialUpperTailLog10(100, 0, 0.5); got != 0 {
		t.Errorf("log10 P(X>=0) = %v, want 0", got)
	}
	// P(X >= n) == p^n == 0.125.
	if got := BinomialUpperTailLog10(3, 3, 0.5); math.Abs(got-math.Log10(0.125)) > 1e-12 {
		t.Errorf("log10 P(X>=3 | n=3,p=.5) = %v, want %v", got, math.Log10(0.125))
	}
	// P(X >= 1 | n=2, p=0.5) == 0.75.
	if got := BinomialUpperTailLog10(2, 1, 0.5); math.Abs(got-math.Log10(0.75)) > 1e-12 {
		t.Errorf("log10 P(X>=1 | n=2,p=.5) = %v, want %v", got, math.Log10(0.75))
	}

	// The regime that matters. Computed as a probability this underflows to
	// exactly 0, which is indistinguishable from an arithmetic failure; in log
	// space it stays a usable number.
	got := BinomialUpperTailLog10(800, 400, OnTheHourProb)
	if math.IsInf(got, 0) || math.IsNaN(got) || got > -100 {
		t.Errorf("far tail log10 = %v, want a large negative number", got)
	}
	if math.Exp(got*math.Ln10) != 0 {
		t.Log("note: this tail is representable after all")
	}
}

func sample(h, m, s int, name string) ClockSample {
	return ClockSample{Hour: h, Min: m, Sec: s, AuthorName: name, Valid: true}
}

func TestAnalyseTimestamps(t *testing.T) {
	t.Run("organic history is not flagged", func(t *testing.T) {
		// Deterministic PRNG rather than a modular pattern. An earlier version
		// of this fixture used i%60 minutes and (i*7)%60 seconds, which
		// coincide every 60 commits and manufactured nine on-the-hour hits --
		// the fixture was wrong, not the test. Real commit times are
		// effectively uniform over the 3600 seconds in an hour.
		rng := rand.New(rand.NewSource(1))
		var ss []ClockSample
		for i := 0; i < 5000; i++ {
			ss = append(ss, sample(rng.Intn(24), rng.Intn(60), rng.Intn(60), "dev"))
		}
		r := AnalyseTimestamps(ss)
		if r.Tier != TierNone {
			t.Errorf("tier = %v, want none (k=%d log10p=%v)", r.Tier, r.OnHour, r.Log10P)
		}
	})

	t.Run("campaign-scale fabrication is strong", func(t *testing.T) {
		var ss []ClockSample
		for i := 0; i < 200; i++ {
			ss = append(ss, sample(12, 0, 0, "persona"))
		}
		for i := 0; i < 50; i++ {
			ss = append(ss, sample(9, 31, 17, "persona"))
		}
		r := AnalyseTimestamps(ss)
		if r.Tier != TierB {
			t.Fatalf("tier = %v, want B", r.Tier)
		}
		if r.DominantHour != 12 {
			t.Errorf("dominant hour = %d, want 12", r.DominantHour)
		}
		if !r.Tier.Expands() {
			t.Error("a fabricated history should license expansion")
		}
	})

	t.Run("small seeding is recorded but does not expand", func(t *testing.T) {
		// Five forged commits: real, but below the agreed count floor. The
		// stated preference is to miss these rather than expand into them.
		var ss []ClockSample
		for i := 0; i < 5; i++ {
			ss = append(ss, sample(12, 0, 0, "persona"))
		}
		for i := 0; i < 95; i++ {
			ss = append(ss, sample(i%24, 1+i%58, 1+i%58, "dev"))
		}
		r := AnalyseTimestamps(ss)
		if r.Tier != TierC {
			t.Fatalf("tier = %v, want C (k=%d log10p=%v)", r.Tier, r.OnHour, r.Log10P)
		}
		if r.Tier.Expands() {
			t.Error("below the count floor must not expand")
		}
	})

	t.Run("bot commits are excluded before the test", func(t *testing.T) {
		var ss []ClockSample
		for i := 0; i < 300; i++ {
			ss = append(ss, sample(0, 0, 0, "dependabot[bot]"))
		}
		for i := 0; i < 40; i++ {
			ss = append(ss, sample(i%24, 1+i%58, 1+i%58, "dev"))
		}
		r := AnalyseTimestamps(ss)
		if r.Tier != TierNone {
			t.Errorf("tier = %v, want none: scheduled automation commits on the hour by design", r.Tier)
		}
		if r.Excluded != 300 {
			t.Errorf("excluded = %d, want 300", r.Excluded)
		}
		if r.Considered != 40 {
			t.Errorf("considered = %d, want 40 (bots must not inflate the denominator)", r.Considered)
		}
	})
}

// Researchers writing up the campaign, and blocklists carrying its domains, are
// true matches -- but they are not compromised, and reporting them as MALICIOUS
// would be both wrong and, published, defamatory.
func TestDocumentaryMatchesCannotReachMalicious(t *testing.T) {
	docs := []Finding{
		{Signal: "indicator-code-search", Tier: TierA, Path: "hacks-and-thefts/vscode-hacks.md", Evidence: "codeprettier.pro"},
		{Signal: "ioc-domain", Tier: TierA, Path: "hacks-and-thefts/vscode-hacks.md", Evidence: "codeprettier.pro"},
	}
	var capped []Finding
	for _, f := range docs {
		capped = append(capped, CapDocumentaryTier(f, true))
	}
	a := Assess(capped)
	if a.Verdict == VerdictMalicious {
		t.Errorf("a research writeup must not be MALICIOUS (got %v: %s)", a.Verdict, a.Reason)
	}
	if a.Expand {
		t.Error("a writeup must not expand the frontier")
	}
	// The evidence itself is retained: this is not suppression.
	for _, f := range capped {
		if f.Evidence == "" || f.Signal == "" {
			t.Error("the finding must be kept in full")
		}
	}
}

// A single documentary mention should not even reach REVIEW.
func TestSingleDocumentaryMentionIsClean(t *testing.T) {
	a := Assess([]Finding{CapDocumentaryTier(
		Finding{Signal: "indicator-code-search", Tier: TierA, Path: "README.md"}, true)})
	if a.Verdict != VerdictClean {
		t.Errorf("verdict = %v, want CLEAN for one mention in prose", a.Verdict)
	}
}

// The campaign's entire delivery mechanism is a JSON file that executes.
func TestExecutingFileKeepsItsTier(t *testing.T) {
	f := CapDocumentaryTier(
		Finding{Signal: "ioc-domain", Tier: TierA, Path: ".vscode/settings.json"}, false)
	if f.Tier != TierA {
		t.Fatalf("tier = %v, want A: settings.json executes", f.Tier)
	}
	if Assess([]Finding{f}).Verdict != VerdictMalicious {
		t.Error("a payload in an executing file must still be MALICIOUS")
	}
}

// Regression: a finding already at TierC must still be marked documentary, or
// two of them pair into a strong signal and the repository comes out MALICIOUS.
func TestAlreadySupportingDocumentaryStillBarredFromEscalation(t *testing.T) {
	fs := []Finding{
		CapDocumentaryTier(Finding{Signal: "curl-pipe-shell", Tier: TierC, Path: "results/x.json"}, true),
		CapDocumentaryTier(Finding{Signal: "remote-eval", Tier: TierC, Path: "results/x.json"}, true),
	}
	for _, f := range fs {
		if !f.Documentary {
			t.Fatalf("%s was not marked documentary", f.Signal)
		}
	}
	if a := Assess(fs); a.Verdict != VerdictClean {
		t.Errorf("verdict = %v, want CLEAN: quoted examples in a results file are not a payload", a.Verdict)
	}
}
