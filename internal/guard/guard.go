// Package guard holds the exclusions that keep an autonomous crawl from
// detonating (tool.md section 8).
//
// These are not refinements. Without the corpus-repository check the first
// malware sample collection the crawler meets fills the frontier with hundreds
// of Tier-A hits; without the vendored-path check every minified bundle on
// GitHub reads as an obfuscated payload.
package guard

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// vendoredPrefixes are directories whose contents are not the repository's own
// code. Obfuscation signals inside them say nothing about the repository.
var vendoredPrefixes = []string{
	"node_modules/", "vendor/", "third_party/", "thirdparty/",
	"dist/", "build/", "out/", "target/", ".next/", ".nuxt/",
	"bower_components/", "jspm_packages/", "site-packages/",
	"testdata/", "fixtures/", "__fixtures__/", "test/fixtures/",
	"__tests__/", "test_project/", "tests/", "spec/", "specs/",
}

var minifiedSuffixes = []string{
	".min.js", ".min.css", ".bundle.js", ".chunk.js", ".map",
	"-min.js", ".packed.js",
}

// IsVendored reports whether a path is third-party or generated content.
//
// Indicator matching still runs on these -- a C2 string inside node_modules is
// a real finding, since that is exactly where a supply-chain payload lands.
// Only the obfuscation and density heuristics are suppressed.
func IsVendored(p string) bool {
	q := strings.ToLower(strings.TrimPrefix(path.Clean("/"+p), "/"))
	for _, pre := range vendoredPrefixes {
		if strings.HasPrefix(q, pre) || strings.Contains(q, "/"+pre) {
			return true
		}
	}
	for _, suf := range minifiedSuffixes {
		if strings.HasSuffix(q, suf) {
			return true
		}
	}
	return false
}

// corpusTopics mark a repository as a deliberate collection of malicious or
// security-testing material.
var corpusTopics = map[string]bool{
	"malware": true, "malware-samples": true, "malware-analysis": true,
	"malware-research": true, "virus": true, "ransomware": true,
	"yara": true, "yara-rules": true, "sigma-rules": true, "detection-rules": true,
	"threat-intelligence": true, "threat-hunting": true, "ioc": true, "iocs": true,
	"security-research": true, "vulnerability-research": true,
	"exploit": true, "exploits": true, "exploit-development": true,
	"poc": true, "proof-of-concept": true, "ctf": true, "ctf-writeups": true,
	"pentest": true, "pentesting": true, "red-team": true, "redteam": true,
	"payloads": true, "shellcode": true, "reverse-engineering": true,
	"honeypot": true, "sandbox": true, "antivirus": true,
}

// corpusNameHints catch repositories whose names announce their contents even
// when topics are absent.
var corpusNameHints = []string{
	// "malicious" was missing here and let ossf/malicious-packages through --
	// a multi-gigabyte catalogue of known-bad packages that is, by
	// construction, wall-to-wall matches for anything this tool hunts.
	"malicious", "malicious-packages", "package-analysis", "bad-packages",
	"typosquat", "dependency-confusion", "supply-chain-attack",
	"security-advisories", "advisory-database", "vulnerability-database",
	"phishing-database", "phishing-kit", "blocklist", "blacklist",
	"malware", "ransomware", "virus-sample", "virussample", "theZoo",
	"yara-rules", "yararules", "sigma", "detection-rules", "iocs",
	"threat-intel", "threatintel", "exploit-db", "exploitdb",
	"payloadsallthethings", "seclists", "awesome-security",
	"awesome-malware", "vx-underground", "vxunderground",
	"ctf-writeups", "ctf-challenges", "security-research",
	// Domain registries and trackers: cirosantilli/expired-domain-names-by-day-2021
	// is 34,000 date-named files of domain names, and every campaign domain that
	// ever expired appears in it.
	"expired-domain", "domain-names", "domain-list", "domainlist",
	"newly-registered", "registered-domains", "domains-by-day", "zone-files",
}

// corpusReadmeHints are phrases a research corpus tends to put up front.
var corpusReadmeHints = []string{
	"for educational purposes only",
	"malware samples",
	"live malware",
	"do not execute",
	"detonate",
	"research purposes only",
	"defanged",
	"sample collection",
	"yara rules",
	"indicators of compromise",
}

// CorpusVerdict explains why a repository was classified as a corpus.
type CorpusVerdict struct {
	IsCorpus bool
	Reason   string
}

// ClassifyCorpus decides whether a repository is a deliberate collection of
// malicious material rather than a victim or an operator asset.
//
// Corpus repositories are recorded but never expanded. They are saturated with
// exactly the signals this tool hunts, and expanding one would consume the
// entire crawl budget confirming that a malware museum contains malware.
func ClassifyCorpus(fullName, description, readmeHead string, topics []string, isFork bool) CorpusVerdict {
	for _, t := range topics {
		if corpusTopics[strings.ToLower(strings.TrimSpace(t))] {
			return CorpusVerdict{true, "repository topic " + strconv.Quote(t)}
		}
	}

	name := strings.ToLower(fullName)
	for _, h := range corpusNameHints {
		if strings.Contains(name, strings.ToLower(h)) {
			return CorpusVerdict{true, "repository name matches research-corpus convention " + strconv.Quote(h)}
		}
	}

	blob := strings.ToLower(description + "\n" + readmeHead)
	hits := 0
	var first string
	for _, h := range corpusReadmeHints {
		if strings.Contains(blob, h) {
			hits++
			if first == "" {
				first = h
			}
		}
	}
	// One phrase is weak -- plenty of ordinary projects say "do not execute".
	// Two independent phrases is a corpus announcing itself.
	if hits >= 2 {
		return CorpusVerdict{true, "description/README reads as a research corpus (" + strconv.Quote(first) + " and " + strconv.Itoa(hits-1) + " more)"}
	}
	return CorpusVerdict{}
}

// CanaryQuery is a search whose result count must never be zero.
//
// The `path:` qualifier silently returns zero results instead of erroring on
// the legacy search API, which once voided four queries that were read as
// "nothing found". Every search batch carries a canary so a backend change
// halts the crawl rather than quietly recording false negatives.
type CanaryQuery struct {
	Query string
	Min   int
}

// DefaultCanary is a term that must always match a large number of public
// files. If it stops matching, the search backend has changed.
func DefaultCanary() CanaryQuery {
	return CanaryQuery{Query: `"folderOpen" language:json`, Min: 1}
}

// CheckCanary reports whether a search backend is behaving.
func CheckCanary(c CanaryQuery, gotResults int) (ok bool, why string) {
	if gotResults >= c.Min {
		return true, ""
	}
	return false, "search canary " + strconv.Quote(c.Query) + " returned " +
		strconv.Itoa(gotResults) + " results (expected at least " + strconv.Itoa(c.Min) +
		"); the search backend or its qualifiers have changed, so zero-result " +
		"queries can no longer be trusted to mean 'not present'"
}

// ---------------------------------------------------------------------------
// Evidence-shape classification
//
// Name and topic heuristics do not reach threat-intelligence feeds:
// 0xDanielLopez/TweetFeed, ElectQ/Soundwave and 0xkoiner/scam-interviews all
// carry campaign domains and none of them announce themselves in the name. But
// they share something structural that a payload cannot fake -- the indicator
// appears in a *list*, not in code that runs.
// ---------------------------------------------------------------------------

// documentaryExts are data and prose formats: things that record an indicator
// rather than act on one.
var documentaryExts = map[string]bool{
	".csv": true, ".tsv": true, ".txt": true, ".md": true, ".rst": true,
	".json": true, ".yaml": true, ".yml": true, ".xml": true, ".log": true,
	".list": true, ".hosts": true, ".conf": true, ".ioc": true, ".stix": true,
}

// executionConfigs are data files that nevertheless execute. The whole point of
// this campaign is that `.vscode/settings.json` is JSON and still runs a shell,
// so extension alone can never decide this.
var executionConfigs = []string{
	".vscode/", ".devcontainer/", ".github/workflows/", ".githooks/",
	"package.json", "composer.json", "pyproject.toml", "cargo.toml",
	".npmrc", ".yarnrc", "makefile", "dockerfile", "docker-compose",
}

// IsExecutionConfig reports whether a path configures something that runs.
func IsExecutionConfig(p string) bool {
	q := strings.ToLower(strings.TrimPrefix(path.Clean("/"+p), "/"))
	base := strings.ToLower(path.Base(q))
	for _, e := range executionConfigs {
		if strings.HasPrefix(q, e) || strings.Contains(q, "/"+e) || base == e {
			return true
		}
	}
	return false
}

// codeExts are source formats. A feed path containing one of these is a tool
// that processes indicators, not a list of them.
var codeExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".py": true, ".go": true, ".rs": true, ".java": true, ".rb": true, ".php": true,
	".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".c": true, ".cpp": true,
	".cs": true, ".swift": true, ".kt": true, ".lua": true, ".pl": true,
}

// IsDocumentary reports whether a path records data rather than executing it.
func IsDocumentary(p string) bool {
	if IsExecutionConfig(p) {
		return false
	}
	ext := strings.ToLower(path.Ext(p))
	if documentaryExts[ext] {
		return true
	}
	// Feeds publish under conventional directories with arbitrary or absent
	// extensions: filters/11-urlhaus.blocky, lists/threat-intel-domain,
	// 2021/10/30/53. The directory says what the file is when the name does not.
	if looksLikeFeedPath(p) && !codeExts[ext] {
		return true
	}
	return false
}

// recordExts are prose and list formats: files whose purpose is to be read, not
// to be loaded by a program as configuration.
var recordExts = map[string]bool{
	".csv": true, ".tsv": true, ".txt": true, ".md": true, ".rst": true,
	".log": true, ".list": true, ".hosts": true, ".ioc": true, ".stix": true,
}

// dataConfigExts are structured-data formats. Unlike prose they are routinely
// parsed by code to decide where to connect and what to run, so an indicator in
// one is as likely to be a configured C2 address as an entry in a list.
var dataConfigExts = map[string]bool{
	".json": true, ".yaml": true, ".yml": true, ".xml": true, ".conf": true,
}

// recordNameHints are file-name fragments that announce an indicator list even
// when the format is structured data (Malicious.json, iocs.yaml, blocklist.xml).
var recordNameHints = []string{
	"ioc", "indicator", "blocklist", "blacklist", "denylist",
	"malicious", "malware", "threat",
}

// IsRecordOnly reports whether a path only records indicators, which is the
// test for capping a finding's tier -- narrower than IsDocumentary on purpose.
//
// IsDocumentary answers "is this the kind of file a catalogue is made of", and
// is paired with positive feed evidence before it condemns a repository to be
// ignored. Capping a tier is a different decision: it lowers a real match, and
// a lowered match on a victim's own config is a missed compromise. So a plain
// data file (config.json, settings.yaml) is NOT capped, because a campaign
// address in one is exactly where a payload reads it from. It is capped only
// when the path or name says it is a list.
func IsRecordOnly(p string) bool {
	if IsExecutionConfig(p) {
		return false
	}
	ext := strings.ToLower(path.Ext(p))
	switch {
	case recordExts[ext]:
		return true
	case dataConfigExts[ext]:
		return looksLikeFeedPath(p) || hasRecordName(p)
	}
	return looksLikeFeedPath(p) && !codeExts[ext]
}

func hasRecordName(p string) bool {
	base := strings.ToLower(path.Base(p))
	for _, h := range recordNameHints {
		if strings.Contains(base, h) {
			return true
		}
	}
	return false
}

// feedPathHints mark the layout conventions of an indicator feed.
var feedPathHints = []string{
	"filters/", "filter_", "feeds/", "feed/", "bundles/", "bundle/",
	"lists/", "list/", "adlist", "adguard", "urlhaus", "rpz/", "mirror/",
	"_posts/", "content/posts/", "content/news/", "threat-intel",
	"blocklist", "blacklist", "denylist", "hostlist", "hosts/",
	"iocs/", "ioc/", "indicators/", "signatures/", "rules/",
	"reports/", "incidents/", "dossier", "advisories/", "advisory/",
	"osv/", "malicious/", "samples/", "corpus/",
}

// datedFile matches the dated-artefact naming a feed uses to publish daily
// snapshots: 20260630.csv, 2026-06-27.json, 202606/....
var datedFile = regexp.MustCompile(`(^|/)(\d{8}|\d{4}-\d{2}-\d{2}|\d{6})\.[a-z]{2,5}$`)

// numericPath matches a path made only of digit segments, optionally with a
// short extension: 01/01/05, 2021/03/17/04, 2021/03/17.txt. Nothing but a
// date-sharded data dump is laid out this way; source code never is.
var numericPath = regexp.MustCompile(`^(?:\d{1,4}/){1,5}\d{1,4}(?:\.[a-z]{2,5})?$`)

// looksLikeFeedPath reports whether a path follows feed publishing conventions.
func looksLikeFeedPath(p string) bool {
	q := strings.ToLower(strings.TrimPrefix(p, "/"))
	for _, h := range feedPathHints {
		if strings.Contains(q, h) {
			return true
		}
	}
	return datedFile.MatchString(q) || numericPath.MatchString(q)
}

// ClassifyByEvidence decides whether a repository documents the campaign rather
// than carrying it, from the paths the indicators were found in.
//
// The test is deliberately conservative, because the cost of being wrong in
// each direction is not symmetric: missing a corpus wastes crawl budget, while
// misclassifying a victim's repository as a corpus means a real compromise goes
// unreported. So documentary paths alone are not enough -- a lure that ships
// its payload as instructions in a README would look documentary too. There
// must also be positive evidence of a feed or collection: publishing
// conventions in the path, or the breadth of matches that a catalogue has and a
// single planted file does not.
func ClassifyByEvidence(paths []string) CorpusVerdict {
	if len(paths) == 0 {
		return CorpusVerdict{}
	}

	distinct := map[string]bool{}
	feedish := 0
	for _, p := range paths {
		if !IsDocumentary(p) {
			// One executable or execution-config hit and this is not a
			// catalogue -- something here runs.
			return CorpusVerdict{}
		}
		distinct[p] = true
		if looksLikeFeedPath(p) {
			feedish++
		}
	}

	switch {
	case feedish > 0:
		return CorpusVerdict{true, "indicator appears in a feed/collection path (" +
			strconv.Itoa(feedish) + " of " + strconv.Itoa(len(distinct)) +
			" matched files), with no executable match anywhere"}
	case len(distinct) >= 3:
		return CorpusVerdict{true, "indicator appears in " + strconv.Itoa(len(distinct)) +
			" data/prose files and no executable one, which is the shape of a catalogue"}
	}
	return CorpusVerdict{}
}
