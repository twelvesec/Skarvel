package guard

import (
	"strings"
	"testing"

	"skarvel/internal/criteria"
)

// A campaign address in a data file the program reads is a configured C2, not a
// list entry: it must keep its tier. Only files that record indicators may be
// capped.
func TestIsRecordOnly(t *testing.T) {
	notRecords := []string{
		"config.json", "src/config/settings.yaml", "server/appsettings.yml",
		"backend/config.xml", "app/app.conf", "src/utils/config.js",
		".vscode/settings.json", ".github/workflows/ci.yml", "package.json",
	}
	for _, p := range notRecords {
		if IsRecordOnly(p) {
			t.Errorf("%s configures behaviour; its tier must not be capped", p)
		}
	}
	records := []string{
		"README.md", "docs/notes.txt", "iocs.csv", "reports/2026-05.md",
		"Ads/Malicious.json",        // a structured file that says it is a list
		"filters/security/f.json",   // feed layout
		"lists/domains.yaml",        // feed layout
		"2026/202606/20260630.csv",  // dated feed snapshot
		"threat-intel/domains.json", // feed layout
	}
	for _, p := range records {
		if !IsRecordOnly(p) {
			t.Errorf("%s only records indicators; it should be capped", p)
		}
	}
	if IsRecordOnly("src/a.js") || IsRecordOnly("lib/tool.py") {
		t.Error("source code is never record-only")
	}
}

// IsDocumentary is deliberately broader (it feeds the corpus check, which
// also demands positive feed evidence), so the two must stay distinct.
func TestIsRecordOnlyIsNarrowerThanIsDocumentary(t *testing.T) {
	if !IsDocumentary("config.json") {
		t.Fatal("IsDocumentary(config.json) changed; the corpus check depends on it")
	}
	if IsRecordOnly("config.json") {
		t.Error("IsRecordOnly(config.json) must be false")
	}
}

// The consequence that motivated the change: the same confirmed-infrastructure
// hit gave opposite verdicts for the same repository depending on whether the
// operator put the address in config.json or README.md.
func TestC2InConfigJSONIsStillMalicious(t *testing.T) {
	verdict := func(p string) criteria.Verdict {
		f := criteria.Finding{Signal: "indicator-domain", Tier: criteria.TierA,
			Subject: criteria.SubjectFile, Path: p}
		return criteria.Assess([]criteria.Finding{criteria.CapDocumentaryTier(f, IsRecordOnly(p))}).Verdict
	}
	if got := verdict("src/config.json"); got != criteria.VerdictMalicious {
		t.Errorf("C2 address in config.json = %v, want MALICIOUS", got)
	}
	if got := verdict("README.md"); got == criteria.VerdictMalicious {
		t.Error("a mention in README.md must stay capped, not MALICIOUS")
	}
}

func TestIsVendored(t *testing.T) {
	vendored := []string{
		"node_modules/lodash/index.js",
		"src/node_modules/x/y.js",
		"vendor/github.com/pkg/errors.go",
		"dist/app.bundle.js",
		"assets/app.min.js",
		"web/static/main.chunk.js",
	}
	for _, p := range vendored {
		if !IsVendored(p) {
			t.Errorf("%q should be treated as vendored/generated", p)
		}
	}
	own := []string{
		"src/index.js",
		"backend/src/compliance/complianceService.js",
		".vscode/tasks.json",
		"cmd/main.go",
		"nodes/handler.js", // must not trip on the "node" prefix
	}
	for _, p := range own {
		if IsVendored(p) {
			t.Errorf("%q is the repository's own code", p)
		}
	}
}

func TestClassifyCorpusByTopic(t *testing.T) {
	v := ClassifyCorpus("someone/collection", "", "", []string{"malware-samples"}, false)
	if !v.IsCorpus {
		t.Fatal("a repository topped 'malware-samples' is a corpus")
	}
	if v.Reason == "" {
		t.Error("a corpus classification must explain itself")
	}
}

func TestClassifyCorpusByName(t *testing.T) {
	if !ClassifyCorpus("ytisf/theZoo", "", "", nil, false).IsCorpus {
		t.Error("theZoo is the canonical sample collection")
	}
	if !ClassifyCorpus("Neo23x0/yara-rules", "", "", nil, false).IsCorpus {
		t.Error("a YARA rule repository is a corpus")
	}
}

// A single cautionary phrase is not enough: ordinary projects say these things.
func TestSingleReadmePhraseIsNotACorpus(t *testing.T) {
	v := ClassifyCorpus("acme/app", "A web app", "Do not execute untrusted input.", nil, false)
	if v.IsCorpus {
		t.Errorf("one phrase should not classify a corpus: %s", v.Reason)
	}
}

func TestTwoReadmePhrasesIsACorpus(t *testing.T) {
	v := ClassifyCorpus("acme/x", "",
		"This repository contains live malware. For educational purposes only.", nil, false)
	if !v.IsCorpus {
		t.Error("two independent corpus phrases should classify")
	}
}

// A victim repository must not be mistaken for a corpus just because a payload
// was pushed into it.
func TestVictimRepoIsNotACorpus(t *testing.T) {
	v := ClassifyCorpus("stockx-fi/stockx_v1", "Decentralised finance backend", "Getting started...", []string{"defi", "web3"}, false)
	if v.IsCorpus {
		t.Errorf("a victim repository is not a corpus: %s", v.Reason)
	}
}

func TestCanaryHaltsOnZero(t *testing.T) {
	ok, why := CheckCanary(DefaultCanary(), 0)
	if ok {
		t.Fatal("a zero-result canary must not pass")
	}
	if why == "" {
		t.Error("the halt must explain that zero results can no longer be trusted")
	}
	if ok, _ := CheckCanary(DefaultCanary(), 384000); !ok {
		t.Error("a healthy canary should pass")
	}
}

// Regression: this repository was cloned during a live run because the name
// hints checked for "malware" but not "malicious".
func TestOSSFMaliciousPackagesIsACorpus(t *testing.T) {
	if !ClassifyCorpus("ossf/malicious-packages", "", "", nil, false).IsCorpus {
		t.Error("ossf/malicious-packages is a catalogue of known-bad packages, not a victim")
	}
	for _, name := range []string{
		"someone/malicious-package-reports",
		"org/security-advisories",
		"x/typosquat-detector",
	} {
		if !ClassifyCorpus(name, "", "", nil, false).IsCorpus {
			t.Errorf("%s should be treated as a corpus", name)
		}
	}
}

// The broader hint list must not start swallowing ordinary projects.
func TestOrdinaryReposStillPass(t *testing.T) {
	for _, name := range []string{
		"stockx-fi/stockx_v1", "acme/web-app", "dan13ram/some-project",
		"vercel/next.js", "expressjs/express",
	} {
		if v := ClassifyCorpus(name, "A normal project", "Install with npm.", []string{"web"}, false); v.IsCorpus {
			t.Errorf("%s wrongly classified as corpus: %s", name, v.Reason)
		}
	}
}

// The feeds a live run surfaced, none of which the name heuristic reaches.
func TestThreatIntelFeedsClassifiedByEvidence(t *testing.T) {
	cases := []struct {
		repo  string
		paths []string
	}{
		{"0xDanielLopez/TweetFeed", []string{"2026/202606/20260630.csv"}},
		{"ElectQ/Soundwave", []string{"bundles/2026-06-27.json"}},
		{"0xkoiner/scam-interviews", []string{"KinetiFi.md", "Other.md", "Third.md"}},
		{"AdguardTeam/HostlistsRegistry", []string{
			"filters/security/filter_11_MaliciousURLBlocklist/filter.txt",
			"assets/filter_11.txt",
		}},
		{"researcher/dossiers", []string{"incidents/2026-05-18-realfraction/iocs.csv"}},
	}
	for _, c := range cases {
		if v := ClassifyByEvidence(c.paths); !v.IsCorpus {
			t.Errorf("%s should be classified as documenting the campaign (paths %v)", c.repo, c.paths)
		}
	}
}

// The whole campaign turns on .vscode/settings.json being JSON and still
// executing. Extension alone must never decide this.
func TestExecutionConfigIsNotDocumentary(t *testing.T) {
	for _, p := range []string{
		".vscode/settings.json", ".vscode/tasks.json", "package.json",
		".github/workflows/ci.yml", ".devcontainer/devcontainer.json",
	} {
		if IsDocumentary(p) {
			t.Errorf("%s executes; it is not documentary", p)
		}
	}
	if v := ClassifyByEvidence([]string{".vscode/settings.json"}); v.IsCorpus {
		t.Error("a settings.json hit is the payload, not a catalogue")
	}
}

// A victim repository must never be written off as a corpus.
func TestVictimEvidenceIsNotACorpus(t *testing.T) {
	cases := [][]string{
		{"backend/src/compliance/complianceService.js"},
		{".vscode/settings.json", "README.md"},
		{"server/utils/authValidator.js", "docs/setup.md"},
		{"README.md"}, // a single prose hit is not enough on its own
		{"docs/a.md", "docs/b.md"},
	}
	for _, paths := range cases {
		if v := ClassifyByEvidence(paths); v.IsCorpus {
			t.Errorf("paths %v wrongly classified as corpus: %s", paths, v.Reason)
		}
	}
}

func TestEvidenceVerdictExplainsItself(t *testing.T) {
	v := ClassifyByEvidence([]string{"filters/blocklist.txt"})
	if !v.IsCorpus || v.Reason == "" {
		t.Error("an evidence-based classification must explain itself")
	}
}

func TestDetectWarningRealWorldNotices(t *testing.T) {
	for name, readme := range map[string]string{
		"real-world-assets": "# real-world-assets\n\nTHIS REPO CONTAINS MALICIOS CODE it is here for investigation purposes only.\nDO NOT DOWNLOAD OR RUN THIS CODE\nDO NOT DOWNLOAD OR RUN THIS CODE",
		"solidity":          "DO NOT clone this repo to your local, this is a repo that contains malicious configurations that will pull code and attack your machine.",
	} {
		if w := DetectWarning("", readme); !w.Found || w.Quote == "" {
			t.Errorf("%s: owner's warning not detected (%+v)", name, w)
		}
	}
}

func TestDetectWarningIgnoresOrdinaryDocs(t *testing.T) {
	for name, readme := range map[string]string{
		"claim only":  "Escapes malicious input before rendering.",
		"advice only": "Do not run this as root. Don't install twice.",
		"far apart": "This library rejects malicious input." + strings.Repeat(" Lorem ipsum dolor sit amet.", 40) +
			" Do not run the tests in production.",
		"empty": "",
	} {
		if w := DetectWarning("", readme); w.Found {
			t.Errorf("%s: wrongly treated as a warning: %q", name, w.Quote)
		}
	}
	// The notice counts only near the top of the README.
	buried := strings.Repeat("Ordinary documentation line.\n", 200) +
		"This repo contains malware. Do not run it."
	if DetectWarning("", buried).Found {
		t.Error("a notice buried far below the head should not count")
	}
}

// cirosantilli/expired-domain-names-by-day-2021 shards its data into
// extensionless date paths (01/01/05). It was reported as MALICIOUS because no
// rule recognised that layout as a feed.
func TestDateShardedFeedIsACorpus(t *testing.T) {
	v := ClassifyByEvidence([]string{"01/01/05", "03/17/22", "12/31/00"})
	if !v.IsCorpus {
		t.Errorf("date-sharded data files should read as a feed: %+v", v)
	}
	if !ClassifyCorpus("cirosantilli/expired-domain-names-by-day-2021", "", "", nil, false).IsCorpus {
		t.Error("an expired-domain tracker is a corpus by name")
	}
	// A numeric path with code in it is still code.
	if ClassifyByEvidence([]string{"01/01/05", "src/run.js"}).IsCorpus {
		t.Error("an executable match anywhere means this is not a catalogue")
	}
	if IsDocumentary("src/app/main") {
		t.Error("an ordinary extensionless path is not a feed")
	}
}
