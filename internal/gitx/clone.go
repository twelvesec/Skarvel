// Package gitx clones repositories and extracts commit metadata offline.
//
// Everything here runs against a blobless bare clone:
//
//	git clone --bare --filter=blob:none
//
// Commits and trees are fetched; blobs are not. Since file *names* live in
// tree objects, `git log --name-status` produces complete per-commit file
// lists without downloading a byte of file content. That is what makes
// scanning a large history cheap enough to do exhaustively.
//
// Two diff features are deliberately avoided during extraction because both
// score file *contents* and would therefore drag blobs down over the network,
// negating the filter: --numstat (line counts) and -M (rename detection).
// Renames consequently appear as a delete plus an add. Line counts and real
// diffs belong to the inspect phase, which fetches blobs only for the commits
// an analyst has already selected.
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// safeConfig hardens git against hostile repositories.
//
// A bare clone never materialises a working tree, so no checkout filters,
// .gitattributes smudge rules, or submodule commands run, and hooks are never
// transferred over the wire. These flags close the remaining edges: hooks are
// pointed at nothing, non-HTTPS transports that can execute commands are
// refused, and credential prompting is disabled so a vanished repo fails fast
// instead of blocking on a password prompt.
var safeConfig = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "protocol.ext.allow=never",
	"-c", "protocol.file.allow=never",
	"-c", "submodule.recurse=false",
	"-c", "credential.helper=",
	"-c", "gc.auto=0",
	"-c", "core.quotePath=true",
	"-c", "advice.detachedHead=false",
}

// run executes git with the safety config applied.
func run(ctx context.Context, dir string, args ...string) (string, error) {
	full := append(append([]string{}, safeConfig...), args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0", // never block waiting for credentials
		"GIT_ASKPASS=true",
		"GIT_CONFIG_NOSYSTEM=1", // ignore machine-wide config
		"LC_ALL=C",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if ctx.Err() != nil {
			return stdout.String(), fmt.Errorf("git %s: %w", args[0], ctx.Err())
		}
		return stdout.String(), &gitError{msg: fmt.Sprintf("git %s: %s", args[0], truncate(msg, 400)), err: err}
	}
	return stdout.String(), nil
}

// gitError keeps the underlying *exec.ExitError reachable through errors.As,
// so callers can act on git's exit status rather than parse its message.
type gitError struct {
	msg string
	err error
}

func (e *gitError) Error() string { return e.msg }
func (e *gitError) Unwrap() error { return e.err }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Clone creates a blobless bare clone of cloneURL at dir.
func Clone(ctx context.Context, cloneURL, dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	return cloneRetry(ctx, dir, "clone",
		"--bare", "--filter=blob:none", "--no-tags", "--quiet", cloneURL, dir)
}

// isTransientNetwork reports whether a clone failure is a temporary network
// fault rather than a statement about the repository.
//
// The distinction matters for a scanner: a DNS blip that is silently recorded
// as "error" for every target looks identical to a completed scan at a glance,
// and a reader can easily mistake "we could not look" for "we looked and found
// nothing".
func isTransientNetwork(err error) bool {
	s := strings.ToLower(err.Error())
	for _, marker := range []string{
		"could not resolve host",
		"connection timed out",
		"connection reset",
		"temporary failure in name resolution",
		"failed to connect",
		"unable to access",
		"early eof",
		"rpc failed",
		"the remote end hung up",
		"tls connect error",
		"operation timed out",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// cloneRetry runs a clone, retrying transient network failures.
func cloneRetry(ctx context.Context, dir string, args ...string) error {
	const attempts = 4
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// A partial clone directory would make the retry fail outright.
			_ = os.RemoveAll(dir)
			if !sleepCtx(ctx, backoff(attempt)) {
				return ctx.Err()
			}
		}
		_, err := run(ctx, "", args...)
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil || !isTransientNetwork(err) {
			return err
		}
	}
	return fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

func backoff(attempt int) time.Duration {
	d := time.Duration(2<<attempt) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// FetchPullRefs pulls every pull request head into refs/pull/*.
//
// This is the highest-value step for hunting malicious code. GitHub retains
// the head commit of every pull request under refs/pull/N/head, including PRs
// that were closed, rejected, or opened from a fork that has since been
// deleted -- code a maintainer refused to merge. A normal clone never fetches
// these refs, so this is the only way to reach that material.
//
// The blob filter is repeated explicitly so the PR fetch stays metadata-only.
func FetchPullRefs(ctx context.Context, dir string) error {
	_, err := run(ctx, dir, "fetch",
		"--filter=blob:none",
		"--no-tags",
		"--quiet",
		"origin", "+refs/pull/*/head:refs/pull/*")
	return err
}

// FetchPullRefsWithBlobs pulls every pull request head, contents included,
// into a clone made with CloneFull.
//
// FetchPullRefs keeps the fetch metadata-only, which suits extraction. Content
// scanning needs the files, and on a full clone a blobless fetch would turn the
// repository into a promisor that later fetches each PR blob one at a time.
func FetchPullRefsWithBlobs(ctx context.Context, dir string) error {
	_, err := run(ctx, dir, "fetch",
		"--no-tags",
		"--quiet",
		"origin", "+refs/pull/*/head:refs/pull/*")
	return err
}

// DefaultBranch resolves the repo's default branch from the clone itself.
//
// A bare clone's HEAD points at whatever the remote's default branch is, which
// is authoritative and costs no API call.
func DefaultBranch(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// IsEmpty reports whether the clone contains no commits at all.
func IsEmpty(ctx context.Context, dir string) bool {
	_, err := run(ctx, dir, "rev-parse", "--verify", "HEAD")
	return err != nil
}

// CountRefs returns how many refs the clone holds, split into branches and
// pull refs, for reporting.
func CountRefs(ctx context.Context, dir string) (branches, pulls int) {
	out, err := run(ctx, dir, "for-each-ref", "--format=%(refname)")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "refs/pull/"):
			pulls++
		case strings.HasPrefix(line, "refs/heads/"):
			branches++
		}
	}
	return branches, pulls
}
