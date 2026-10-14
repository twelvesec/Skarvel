package gitx

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CloneFull makes a bare clone including blobs.
//
// Content scanning needs file contents, which the blobless clone deliberately
// omits. Grepping a promisor clone would fetch blobs one object at a time over
// the network, so pulling everything up front is dramatically faster once the
// content of more than a handful of files is wanted.
func CloneFull(ctx context.Context, cloneURL, dir string) error {
	return cloneRetry(ctx, dir, "clone", "--bare", "--no-tags", "--quiet", cloneURL, dir)
}

// CommitMeta is one commit's identity and timing, with no author filtering.
//
// Scanning is repo-scoped rather than user-scoped: a repository can be
// compromised by any contributor, so restricting to one author would miss
// payloads planted under other identities.
type CommitMeta struct {
	SHA string
	// AuthorLocal is the author time as the committer's own clock recorded it,
	// including their UTC offset. The local wall-clock reading is what exposes
	// generated history, since a generator stamps a fixed local hour while the
	// UTC instant varies per persona timezone.
	AuthorLocal    string
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	Subject        string
}

// LocalClock returns the hour, minute and second of the author's local time.
func (c CommitMeta) LocalClock() (h, m, s int, ok bool) {
	t := strings.Index(c.AuthorLocal, "T")
	if t < 0 || len(c.AuthorLocal) < t+9 {
		return 0, 0, 0, false
	}
	parts := strings.Split(c.AuthorLocal[t+1:t+9], ":")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	var err error
	if h, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, 0, false
	}
	if m, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, false
	}
	if s, err = strconv.Atoi(parts[2]); err != nil {
		return 0, 0, 0, false
	}
	return h, m, s, true
}

// OnTheHour reports whether the author's local time has zero minutes and
// seconds -- a 1-in-3600 coincidence for an organic commit.
func (c CommitMeta) OnTheHour() bool {
	_, m, s, ok := c.LocalClock()
	return ok && m == 0 && s == 0
}

// AtLocalHour reports whether the author's local time is exactly hour:00:00.
func (c CommitMeta) AtLocalHour(hour int) bool {
	h, m, s, ok := c.LocalClock()
	return ok && h == hour && m == 0 && s == 0
}

// AuthorDate parses the author timestamp.
func (c CommitMeta) AuthorDate() time.Time {
	t, err := time.Parse(time.RFC3339, c.AuthorLocal)
	if err != nil {
		return time.Time{}
	}
	return t
}

// LogAll returns every commit on every ref, unfiltered by author.
func LogAll(ctx context.Context, dir string) ([]CommitMeta, error) {
	const format = "--pretty=format:%H\x1f%aI\x1f%an\x1f%ae\x1f%cn\x1f%ce\x1f%s"
	out, err := run(ctx, dir, "log", "--all", "--no-merges=false", format)
	if err != nil {
		// Older git rejects --no-merges=false; retry without it.
		if out, err = run(ctx, dir, "log", "--all", format); err != nil {
			return nil, err
		}
	}

	var commits []CommitMeta
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) < 7 {
			continue
		}
		commits = append(commits, CommitMeta{
			SHA: f[0], AuthorLocal: f[1], AuthorName: f[2], AuthorEmail: f[3],
			CommitterName: f[4], CommitterEmail: f[5], Subject: f[6],
		})
	}
	return commits, nil
}

// RefTips returns the commit object of every ref, for grepping the current
// state of all branches and pull refs without walking full history.
func RefTips(ctx context.Context, dir string) ([]string, error) {
	out, err := run(ctx, dir, "for-each-ref", "--format=%(objectname)")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var tips []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !seen[line] {
			seen[line] = true
			tips = append(tips, line)
		}
	}
	return tips, nil
}

// AllCommits returns every commit object in the repository, for a deep grep
// that also sees content which was later removed.
func AllCommits(ctx context.Context, dir string, limit int) ([]string, error) {
	args := []string{"rev-list", "--all"}
	if limit > 0 {
		args = append(args, "--max-count="+strconv.Itoa(limit))
	}
	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	var shas []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			shas = append(shas, line)
		}
	}
	return shas, nil
}

// GrepHit is one regex match inside a tracked file.
type GrepHit struct {
	Rev  string
	Path string
	Line int
	Text string
}

// Grep runs an extended-regex search over the given revisions.
//
// Binary files are skipped and matches are capped per invocation, so a minified
// bundle that matches on every line cannot swamp the report.
func Grep(ctx context.Context, dir, pattern string, revs []string, maxHits int) ([]GrepHit, error) {
	if len(revs) == 0 {
		return nil, nil
	}
	args := []string{"grep", "-I", "-n", "-E", "--no-color", "-e", pattern}
	args = append(args, revs...)
	args = append(args, "--")

	out, err := run(ctx, dir, args...)
	if err != nil {
		// Exit status 1 means nothing matched, which is not an error. Anything
		// else -- a pattern git rejects, a corrupt repository -- must surface:
		// returning no hits here would report a failed scan as a clean one.
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var hits []GrepHit
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		// Format is <rev>:<path>:<lineno>:<text>
		rev, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		path, rest2, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		numStr, text, ok := strings.Cut(rest2, ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(numStr)
		if err != nil {
			continue
		}
		hits = append(hits, GrepHit{Rev: rev, Path: path, Line: n, Text: text})
		if maxHits > 0 && len(hits) >= maxHits {
			break
		}
	}
	return hits, nil
}
