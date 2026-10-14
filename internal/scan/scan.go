// Package scan inspects whole repositories for signs of fabricated history and
// planted code, with no author filter.
//
// This is deliberately the inverse of a hunt. A hunt asks "what did this person
// touch"; a scan asks "is this repository compromised". Compromise is a
// property of the repository, not of one contributor -- a payload planted under
// a second identity is invisible to any author-scoped query.
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"skarvel/internal/gitx"
)

// Tier expresses how much weight a signature carries on its own.
//
// Severity alone proved insufficient: a lone `curl | sh` is genuinely
// high-risk, but on developer tooling it is also the documented install path
// for half the ecosystem, so treating it as conclusive buried real findings
// under routine toolchain setup. Tier separates "dangerous" from "diagnostic".
type Tier string

const (
	// TierDefinitive matches known campaign infrastructure. One hit settles it.
	TierDefinitive Tier = "definitive"
	// TierStrong matches a mechanism that is very rarely legitimate --
	// executing a network response as code, or hijacking an editor's terminal.
	// One hit is enough.
	TierStrong Tier = "strong"
	// TierSupporting matches practices that are suspicious in combination but
	// common in isolation. Two distinct supporting signatures in one file
	// escalate; one alone only warrants review.
	TierSupporting Tier = "supporting"
)

// Signature is a content pattern worth flagging.
type Signature struct {
	Name     string
	Severity string // high | medium -- display only
	Tier     Tier   // how much weight it carries toward a verdict
	// Pattern must mean the same as POSIX ERE (scan runs it through
	// git grep -E) and as Go regexp (the crawler). Both match line by line, so
	// "." never crosses a newline; never write "[^\n]", which ERE reads as
	// "not a backslash and not the letter n".
	Pattern string
	Why     string
}

// Signatures are structural rather than name-based on purpose.
//
// Filenames proved useless for generalising across the campaign that motivated
// this: four repositories used four different names for the same payload. What
// stayed constant was the mechanism -- fetch a remote response, hand it to a
// dynamic code constructor -- and the configuration around it.
var Signatures = []Signature{
	{
		Name: "ioc-domain", Severity: "high", Tier: TierDefinitive,
		Pattern: `codeprettier\.pro|code-beautify\.com|ipregionchecker\.(org|net|com)|isillegalregion\.com|nomg[uw]enya\.co\.za|gist\.githubusercontent\.com/cuda-toolkit`,
		Why:     "known command-and-control domain",
	},
	{
		Name: "dynamic-require", Severity: "high", Tier: TierStrong,
		Pattern: `(Function\.constructor|new Function)[^;]{0,80}require`,
		Why:     "builds a function from data and grants it module access",
	},
	{
		Name: "remote-eval", Severity: "high", Tier: TierStrong,
		Pattern: `eval\([[:space:]]*(data|body|res|resp|response|r)(\.[A-Za-z_][A-Za-z0-9_]*)*[[:space:]]*\)`,
		Why:     "evaluates a network response as code",
	},
	{
		Name: "curl-pipe-shell", Severity: "high", Tier: TierSupporting,
		// Quotes must stay inside the run: real payloads quote the URL, so
		// excluding them here would miss the very samples this was written for.
		// git grep is line-based, so [^|] cannot run past the end of a line.
		Pattern: `(curl|wget)[^|]{0,160}\|[[:space:]]*(ba|z|k)?sh`,
		Why:     "downloads and pipes straight into a shell",
	},
	{
		Name: "vscode-terminal-hijack", Severity: "high", Tier: TierStrong,
		Pattern: `terminal\.integrated\.profiles.{0,400}(curl|wget|powershell|Invoke-WebRequest)`,
		Why:     "editor terminal profile that executes a remote payload on open",
	},
	{
		Name: "defender-exclusion", Severity: "high", Tier: TierStrong,
		Pattern: `Add-MpPreference|ExclusionPath`,
		Why:     "adds an antivirus exclusion",
	},
	{
		Name: "powershell-download-exec", Severity: "high", Tier: TierStrong,
		Pattern: `(iex|Invoke-Expression)[[:space:]]*\(?[[:space:]]*(iwr|Invoke-WebRequest|New-Object[[:space:]]+Net\.WebClient|curl)`,
		Why:     "PowerShell download-and-execute in one expression",
	},
	{
		// A task with runOn:folderOpen executes the moment the folder is opened
		// -- no terminal, no build, no user action. That makes tasks.json a
		// sharper vector than the settings.json terminal hijack, which at least
		// waits for the victim to open a shell.
		// Agreed at Tier B (strong): this is the campaign's signature delivery
		// vector, and a task that runs on folderOpen executes with no user
		// action at all. Ordinary build tasks do use folderOpen, which is why
		// it is strong rather than definitive.
		Name: "vscode-autorun-task", Severity: "high", Tier: TierStrong,
		Pattern: `"runOn"[[:space:]]*:[[:space:]]*"folderOpen"`,
		Why:     "editor task configured to run automatically on folder open",
	},
	{
		Name: "hidden-window-exec", Severity: "medium", Tier: TierSupporting,
		Pattern: `-WindowStyle[^A-Za-z0-9]{1,6}Hidden|"reveal"[[:space:]]*:[[:space:]]*"never"`,
		Why:     "suppresses any visible window or output for the executed command",
	},
	{
		Name: "b64-https", Severity: "medium", Tier: TierSupporting,
		Pattern: `aHR0cHM6Ly`,
		Why:     "base64-encoded https:// URL, commonly used to hide a C2 endpoint",
	},
	{
		Name: "secret-header", Severity: "medium", Tier: TierSupporting,
		Pattern: `x-secret-header`,
		Why:     "custom authentication header seen in this payload family",
	},
	{
		Name: "dev-key-config", Severity: "medium", Tier: TierSupporting,
		Pattern: `DEV_API_KEY|DEV_SECRET_KEY|DEV_SECRET_VALUE`,
		Why:     "config key names used to smuggle C2 details past review",
	},
	{
		Name: "hidden-from-explorer", Severity: "medium", Tier: TierSupporting,
		Pattern: `"files\.exclude".{0,200}\.vscode`,
		Why:     "hides its own directory from the editor file tree",
	},
	{
		Name: "whitespace-padding", Severity: "medium", Tier: TierSupporting,
		Pattern: `[ ]{80,}[^ ]`,
		Why:     "long run of spaces pushing code off-screen in review",
	},
}

// wellKnownInstallers are hosts whose curl-pipe-shell one-liners are the
// documented install path for common developer tooling.
//
// Matches against them are downgraded rather than suppressed: piping a remote
// script into a shell is genuinely dangerous whoever serves it, and a lookalike
// domain is exactly how this would be abused. The goal is only to stop routine
// toolchain setup from outranking real findings in triage.
var wellKnownInstallers = []string{
	"foundry.paradigm.xyz",
	"sh.rustup.rs",
	"get.docker.com",
	"deb.nodesource.com",
	"raw.githubusercontent.com/nvm-sh",
	"get.pnpm.io",
	"bun.sh/install",
	"astral.sh/uv/install.sh",
	"install.python-poetry.org",
	"proto.moonrepo.dev",
}

// downgradeKnownInstallers relabels benign toolchain bootstraps.
func downgradeKnownInstallers(hits []Hit) []Hit {
	for i, h := range hits {
		if h.Signature != "curl-pipe-shell" {
			continue
		}
		for _, host := range wellKnownInstallers {
			if strings.Contains(h.Text, host) {
				hits[i].Severity = "medium"
				hits[i].Tier = TierSupporting
				hits[i].Signature = "curl-pipe-shell (known installer)"
				hits[i].Why = "pipes a remote script into a shell, but from a recognised toolchain host"
				break
			}
		}
	}
	return hits
}

// Config tunes a scan.
type Config struct {
	WorkDir     string
	Concurrency int
	// TimestampsOnly uses a blobless clone and skips content scanning, which
	// makes wide sweeps over many candidate repos cheap.
	TimestampsOnly bool
	// Deep greps every commit rather than only the tip of each ref, catching
	// content that was added and later removed.
	Deep        bool
	DeepLimit   int
	KeepClones  bool
	RepoTimeout time.Duration
	Logf        func(string, ...any)
	// Platform selects where "owner/repo" is cloned from: "github" (default
	// when empty) or "bitbucket".
	Platform string
}

// CloneURL returns the HTTPS clone address of owner/repo on the configured
// platform.
func (c Config) CloneURL(repo string) string {
	if c.Platform == "bitbucket" {
		return "https://bitbucket.org/" + repo + ".git"
	}
	return "https://github.com/" + repo + ".git"
}

// AuthorStat summarises one contributor's timing fingerprint.
type AuthorStat struct {
	Name    string
	Email   string
	Commits int
	OnHour  int
	// TopHour is the local hour that accounts for the most commits, with the
	// count, which identifies the fixed hour a generator stamps.
	TopHour      int
	TopHourCount int
	First, Last  string
}

// Forged reports whether every one of this author's commits lands exactly on a
// local hour boundary.
func (a AuthorStat) Forged() bool {
	return a.Commits >= 3 && a.OnHour == a.Commits
}

// Hit is one content match.
type Hit struct {
	Signature string
	Severity  string
	Tier      Tier
	Path      string
	Line      int
	Rev       string
	Text      string
	Why       string
}

// RepoResult is the outcome for one repository.
type RepoResult struct {
	Repo    string
	Err     error
	Commits int
	OnHour  int
	Authors []AuthorStat
	Hits    []Hit
	Skipped bool
}

// ForgedRatio is the share of commits stamped exactly on a local hour.
func (r RepoResult) ForgedRatio() float64 {
	if r.Commits == 0 {
		return 0
	}
	return float64(r.OnHour) / float64(r.Commits)
}

// HighSeverity counts high-severity content hits.
func (r RepoResult) HighSeverity() int {
	n := 0
	for _, h := range r.Hits {
		if h.Severity == "high" {
			n++
		}
	}
	return n
}

// Verdict renders an overall judgement.
//
// The timestamp test carries most of the weight: organic commits scatter across
// the minute, so a repository where every commit lands on an exact hour is
// generated, not written.
func (r RepoResult) Verdict() string {
	switch {
	case r.Err != nil:
		return "ERROR"
	case r.Commits == 0:
		return "EMPTY"
	case r.OnHour == r.Commits && r.Commits >= 10:
		return "FABRICATED"
	case r.ForgedRatio() > 0.5:
		return "SUSPECT"
	case r.Conclusive():
		return "MALICIOUS CONTENT"
	case len(r.Hits) > 0:
		return "REVIEW"
	}
	return "clean"
}

// Conclusive reports whether the content hits alone justify calling a
// repository malicious.
//
// A single definitive or strong hit suffices. Supporting signatures escalate
// only when at least two *distinct* ones land in the same file: `curl | sh` in
// isolation is how much of the ecosystem documents installation, whereas
// `curl | sh` alongside a base64 endpoint in one file is not.
func (r RepoResult) Conclusive() bool {
	perFile := map[string]map[string]bool{}

	for _, h := range r.Hits {
		switch h.Tier {
		case TierDefinitive, TierStrong:
			return true
		case TierSupporting:
			if perFile[h.Path] == nil {
				perFile[h.Path] = map[string]bool{}
			}
			perFile[h.Path][h.Signature] = true
		}
	}
	for _, sigs := range perFile {
		if len(sigs) >= 2 {
			return true
		}
	}
	return false
}

func (c *Config) logf(f string, a ...any) {
	if c.Logf != nil {
		c.Logf(f, a...)
	}
}

// Run scans the given repositories concurrently.
func Run(ctx context.Context, repos []string, cfg Config) []RepoResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.RepoTimeout <= 0 {
		cfg.RepoTimeout = 20 * time.Minute
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return []RepoResult{{Repo: "-", Err: err}}
	}

	results := make([]RepoResult, len(repos))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = scanOne(ctx, repos[idx], cfg)
				r := results[idx]
				if r.Err != nil {
					cfg.logf("%-46s  ERROR  %v", r.Repo, r.Err)
				} else {
					cfg.logf("%-46s  %-18s  %d/%d on-the-hour, %d content hits",
						r.Repo, r.Verdict(), r.OnHour, r.Commits, len(r.Hits))
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range repos {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()
	wg.Wait()
	return results
}

func scanOne(ctx context.Context, repo string, cfg Config) RepoResult {
	res := RepoResult{Repo: repo}

	rctx, cancel := context.WithTimeout(ctx, cfg.RepoTimeout)
	defer cancel()

	dir := filepath.Join(cfg.WorkDir, "scan__"+strings.ReplaceAll(repo, "/", "__")+".git")
	if err := os.RemoveAll(dir); err != nil {
		res.Err = err
		return res
	}
	if !cfg.KeepClones {
		defer os.RemoveAll(dir)
	}

	url := cfg.CloneURL(repo)
	var err error
	if cfg.TimestampsOnly {
		err = gitx.Clone(rctx, url, dir)
	} else {
		err = gitx.CloneFull(rctx, url, dir)
	}
	if err != nil {
		res.Err = err
		return res
	}
	// Pull requests carry code that was proposed and never merged, which is
	// exactly where a rejected payload would still be reachable. Only GitHub
	// exposes them as refs/pull/*; Bitbucket Cloud does not publish PR heads
	// over git, so there the walk covers branches and tags only.
	if cfg.Platform != "bitbucket" {
		_ = gitx.FetchPullRefs(rctx, dir)
	}

	commits, err := gitx.LogAll(rctx, dir)
	if err != nil {
		res.Err = err
		return res
	}
	res.Commits = len(commits)
	res.Authors = summarise(commits, &res.OnHour)

	if !cfg.TimestampsOnly {
		if res.Hits, err = contentScan(rctx, dir, cfg); err != nil {
			res.Err = fmt.Errorf("content scan: %w", err)
		}
	}
	return res
}

// summarise builds per-author timing fingerprints.
func summarise(commits []gitx.CommitMeta, totalOnHour *int) []AuthorStat {
	type acc struct {
		AuthorStat
		hours map[int]int
	}
	byAuthor := map[string]*acc{}

	for _, c := range commits {
		key := strings.ToLower(c.AuthorName + "\x00" + c.AuthorEmail)
		a, ok := byAuthor[key]
		if !ok {
			a = &acc{
				AuthorStat: AuthorStat{Name: c.AuthorName, Email: c.AuthorEmail},
				hours:      map[int]int{},
			}
			byAuthor[key] = a
		}
		a.Commits++
		if h, _, _, ok := c.LocalClock(); ok {
			a.hours[h]++
		}
		if c.OnTheHour() {
			a.OnHour++
			*totalOnHour++
		}
		d := c.AuthorLocal
		if len(d) >= 10 {
			d = d[:10]
			if a.First == "" || d < a.First {
				a.First = d
			}
			if d > a.Last {
				a.Last = d
			}
		}
	}

	out := make([]AuthorStat, 0, len(byAuthor))
	for _, a := range byAuthor {
		for h, n := range a.hours {
			if n > a.TopHourCount {
				a.TopHour, a.TopHourCount = h, n
			}
		}
		out = append(out, a.AuthorStat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Forged() != out[j].Forged() {
			return out[i].Forged()
		}
		return out[i].Commits > out[j].Commits
	})
	return out
}

// contentScan greps the repository for every signature. An error means the
// content was not fully examined, so the repository must not be called clean.
func contentScan(ctx context.Context, dir string, cfg Config) ([]Hit, error) {
	var revs []string
	var err error
	if cfg.Deep {
		limit := cfg.DeepLimit
		if limit == 0 {
			limit = 500
		}
		revs, err = gitx.AllCommits(ctx, dir, limit)
	} else {
		revs, err = gitx.RefTips(ctx, dir)
	}
	if err != nil {
		return nil, err
	}
	if len(revs) == 0 {
		return nil, nil
	}

	// The same file and line repeats across every ref that contains it, so
	// results are collapsed to one row per (signature, path, line).
	seen := map[string]bool{}
	var hits []Hit

	for _, sig := range Signatures {
		raw, err := gitx.Grep(ctx, dir, sig.Pattern, revs, 4000)
		if err != nil {
			return nil, fmt.Errorf("signature %s: %w", sig.Name, err)
		}
		for _, h := range raw {
			key := sig.Name + "\x00" + h.Path + "\x00" + fmt.Sprint(h.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			text := strings.TrimSpace(h.Text)
			if len(text) > 120 {
				text = text[:120] + "…"
			}
			hits = append(hits, Hit{
				Signature: sig.Name, Severity: sig.Severity, Tier: sig.Tier, Why: sig.Why,
				Path: h.Path, Line: h.Line, Rev: h.Rev, Text: text,
			})
		}
	}

	hits = downgradeKnownInstallers(hits)
	sort.Slice(hits, func(i, j int) bool {
		if (hits[i].Severity == "high") != (hits[j].Severity == "high") {
			return hits[i].Severity == "high"
		}
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].Line < hits[j].Line
	})
	return hits, nil
}

// CompiledPattern returns a compiled matcher for a signature, cached.
//
// The crawler evaluates signatures against file contents in-process rather than
// shelling out to `git grep` per repository, so it needs the patterns as Go
// regexps. Compilation is cached because the set is fixed and the crawl applies
// it to every file it reads.
func CompiledPattern(s Signature) *regexp.Regexp {
	patternCacheMu.Lock()
	defer patternCacheMu.Unlock()
	if re, ok := patternCache[s.Pattern]; ok {
		return re
	}
	re, err := regexp.Compile(s.Pattern)
	if err != nil {
		// POSIX-only constructs are rare here; a pattern that will not compile
		// is recorded as nil so it is skipped rather than retried per file.
		re = nil
	}
	patternCache[s.Pattern] = re
	return re
}

var (
	patternCacheMu sync.Mutex
	patternCache   = map[string]*regexp.Regexp{}
)
