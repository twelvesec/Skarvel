package crawl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"skarvel/internal/criteria"
	"skarvel/internal/event"
	"skarvel/internal/ghapi"
	"skarvel/internal/gitx"
	"skarvel/internal/guard"
	"skarvel/internal/indicator"
	"skarvel/internal/scan"
)

// GitAnalyzer is the real repository examiner: clone, scan, analyse history,
// then throw the clone away.
//
// Clones are evicted rather than cached. Several hundred retained clones is
// what turns a long crawl into a full disk, and by eviction time everything
// worth keeping has already become a finding.
type GitAnalyzer struct {
	CacheDir string
	Bus      *event.Bus
	Budget   *Budget

	// Platform is criteria.HostGitHub or criteria.HostBitbucket. Only GitHub
	// publishes pull-request heads over git.
	Platform string

	// MaxFileBytes bounds how much of any one file is read. The stage-2 payload
	// in the seed campaign was 3.9 MB on a single line; reading it whole is
	// affordable, reading a 500 MB model checkpoint is not.
	MaxFileBytes int64

	// MaxFiles bounds how many distinct file versions are read per repository.
	MaxFiles int

	// RepoTimeout bounds one repository's clone and analysis, so a single
	// pathological repository cannot consume the whole crawl.
	RepoTimeout time.Duration
}

func NewGitAnalyzer(cacheDir string, bus *event.Bus, b *Budget) *GitAnalyzer {
	return &GitAnalyzer{
		CacheDir: cacheDir, Bus: bus, Budget: b,
		MaxFileBytes: 8 << 20, MaxFiles: 20000, RepoTimeout: 20 * time.Minute,
	}
}

var scanExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".json": true, ".py": true, ".sh": true, ".bash": true, ".zsh": true,
	".ps1": true, ".bat": true, ".cmd": true, ".rb": true, ".php": true,
	".go": true, ".rs": true, ".java": true, ".yml": true, ".yaml": true,
	".toml": true, ".env": true, ".md": true, ".txt": true, ".lock": true,
	".npl": true, // the campaign's stage-3 payload, renamed to dodge *.js scanners
}

func scannable(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	if scanExtensions[ext] {
		return true
	}
	base := strings.ToLower(filepath.Base(p))
	return base == "dockerfile" || base == "makefile" || base == "package.json" ||
		strings.HasPrefix(base, ".npmrc") || strings.HasPrefix(base, ".bashrc") ||
		strings.HasPrefix(base, ".env")
}

func (a *GitAnalyzer) logf(repo, format string, args ...any) {
	if a.Bus != nil {
		a.Bus.Emit(event.Event{Kind: event.KindLog, Repo: repo, Message: fmt.Sprintf(format, args...)})
	}
}

// Analyze implements Analyzer.
func (a *GitAnalyzer) Analyze(ctx context.Context, repo string, meta *ghapi.RepoMeta, inds *indicator.Set) (Analysis, error) {
	var res Analysis

	if a.RepoTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.RepoTimeout)
		defer cancel()
	}

	// Every platform client fills CloneURL; the GitHub form is only a fallback
	// for metadata that arrived without one (tests, cached nodes).
	cloneURL := meta.CloneURL
	if cloneURL == "" {
		cloneURL = "https://github.com/" + repo + ".git"
	}
	dir := filepath.Join(a.CacheDir, strings.ReplaceAll(repo, "/", "__")+".git")
	_ = os.RemoveAll(dir) // a leftover from an interrupted visit would fail the clone

	if err := gitx.CloneFull(ctx, cloneURL, dir); err != nil {
		os.RemoveAll(dir)
		return res, err
	}
	defer os.RemoveAll(dir)

	// Pull requests carry code that was proposed and never merged, which is
	// exactly where a rejected payload stays reachable. Bitbucket Cloud does
	// not publish PR heads over git, so there the walk covers branches only.
	// A failure here narrows the scan but does not void it.
	if a.Platform != criteria.HostBitbucket {
		if err := gitx.FetchPullRefsWithBlobs(ctx, dir); err != nil {
			a.logf(repo, "pull-request refs not fetched: %v", err)
		}
	}

	size := dirSize(dir)
	a.Budget.SpendDisk(size)
	defer a.Budget.ReleaseDisk(size)

	// History analysis covers every ref, not just the default branch: the seed
	// campaign planted payloads on non-default branches specifically.
	commits, err := gitx.LogAll(ctx, dir)
	if err == nil {
		samples := toClockSamples(commits)
		res.Timestamps = criteria.AnalyseTimestamps(samples)
		for _, p := range criteria.ForgedPersonas(samples) {
			res.Findings = append(res.Findings, p.ToFinding(repo))
		}
	}

	revs, err := gitx.RefTips(ctx, dir)
	if err != nil || len(revs) == 0 {
		revs = []string{"HEAD"}
	}

	type flagged struct{ rev, path string }
	var flaggedFiles []flagged
	flaggedPath := map[string]bool{}
	seenBlob := map[string]bool{}
	filesScanned := 0

	for _, rev := range revs {
		if ctx.Err() != nil {
			break
		}
		tree, err := gitx.ListBlobs(ctx, dir, rev)
		if err != nil {
			continue
		}
		// Blobs are requested by object ID and the path is kept alongside, not
		// encoded into the request: a path is attacker-chosen and git allows a
		// newline in one, which would corrupt the request/response pairing.
		var oids, paths []string
		for _, b := range tree {
			if filesScanned >= a.MaxFiles {
				break
			}
			// Deduplicate by content, not by path: the same path carrying a
			// different blob on a side branch is precisely what must be read.
			if seenBlob[b.OID] || !scannable(b.Path) {
				continue
			}
			seenBlob[b.OID] = true
			filesScanned++
			oids = append(oids, b.OID)
			paths = append(paths, b.Path)
		}
		if len(oids) == 0 {
			continue
		}

		// Streamed: one blob in memory at a time, and anything over MaxFileBytes
		// is skipped without being allocated.
		err = gitx.CatBlobs(ctx, dir, oids, a.MaxFileBytes, func(i int, blob gitx.Blob) error {
			if err := ctx.Err(); err != nil {
				return err // the repository timeout must be able to stop a long file loop
			}
			path := paths[i]
			if gitx.IsBinary(blob.Data) {
				return nil
			}

			// Indicator matching runs everywhere, including vendored trees: a
			// C2 string inside node_modules is exactly where a supply-chain
			// payload lands.
			//
			// Only files that record indicators (prose, feeds) have their tier
			// capped; a data file that configures behaviour, such as config.json,
			// is not "documentary" -- a C2 address in one is a real finding.
			doc := guard.IsRecordOnly(path)
			hit := false
			for _, f := range inds.Match(repo, path, blob.Data) {
				f.SHA = rev // anchors the permalink to a commit, not a branch
				res.Findings = append(res.Findings, criteria.CapDocumentaryTier(f, doc))
				hit = true
			}

			// Heuristic signatures are suppressed on third-party and generated
			// code, which is otherwise the single largest false-positive source.
			if !guard.IsVendored(path) {
				for _, f := range matchSignatures(repo, path, blob.Data) {
					f.SHA = rev
					res.Findings = append(res.Findings, criteria.CapDocumentaryTier(f, doc))
					hit = true
				}
			}

			if hit {
				flaggedFiles = append(flaggedFiles, flagged{rev, path})
				flaggedPath[path] = true
				// Mine candidate indicators only from files that carry a hit.
				res.Candidates = append(res.Candidates, indicator.Extract(repo, path, blob.Data)...)
			}
			return nil
		})
		if err != nil && ctx.Err() == nil {
			a.logf(repo, "reading files at %s: %v", rev, err)
		}
	}

	// Authorship of the flagged files, which is what expansion follows. Asked
	// at the ref the file was flagged on, so a payload that only ever existed
	// on a side branch or a pull request still yields its author.
	seenAuthor := map[string]bool{}
	seenQuery := map[string]bool{}
	for _, ff := range flaggedFiles {
		if seenQuery[ff.rev+"\x00"+ff.path] {
			continue
		}
		seenQuery[ff.rev+"\x00"+ff.path] = true
		authors, err := gitx.AuthorsOfPath(ctx, dir, ff.rev, ff.path, 20)
		if err != nil {
			continue
		}
		for _, au := range authors {
			if criteria.IsBot(au.Name, au.Email) {
				continue
			}
			k := au.Name + "|" + au.Email
			if seenAuthor[k] {
				continue
			}
			seenAuthor[k] = true
			res.Authors = append(res.Authors, Identity{Name: au.Name, Email: au.Email})
		}
	}

	if ctx.Err() != nil && len(res.Findings) == 0 {
		return res, fmt.Errorf("analysis of %s did not finish: %w", repo, ctx.Err())
	}
	return res, nil
}

// matchSignatures runs the existing tiered scanner over one file's contents.
func matchSignatures(repo, path string, data []byte) []criteria.Finding {
	var out []criteria.Finding
	lines := strings.Split(string(data), "\n")

	for _, sig := range scan.Signatures {
		re := scan.CompiledPattern(sig)
		if re == nil {
			continue
		}
		for i, line := range lines {
			if !re.MatchString(line) {
				continue
			}
			tier, err := criteria.ParseTier(string(sig.Tier))
			if err != nil {
				tier = criteria.TierC
			}
			out = append(out, criteria.Finding{
				Signal:   sig.Name,
				Tier:     tier,
				Subject:  criteria.SubjectFile,
				Repo:     repo,
				Path:     path,
				Line:     i + 1,
				Why:      sig.Why,
				Evidence: truncate(strings.TrimSpace(line), 160),
			})
			break // one hit per signature per file is enough to characterise it
		}
	}
	return out
}

func toClockSamples(cs []gitx.CommitMeta) []criteria.ClockSample {
	out := make([]criteria.ClockSample, 0, len(cs))
	for _, c := range cs {
		h, m, s, ok := c.LocalClock()
		out = append(out, criteria.ClockSample{
			SHA: c.SHA, Hour: h, Min: m, Sec: s, Valid: ok,
			AuthorName: c.AuthorName, AuthorEmail: c.AuthorEmail,
			CommitterName: c.CommitterName, CommitterEmail: c.CommitterEmail,
		})
	}
	return out
}

func dirSize(dir string) int64 {
	var total int64
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
