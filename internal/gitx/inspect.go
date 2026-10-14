package gitx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnsureClone returns a usable clone directory for a repo, reusing one that is
// already present and creating it otherwise.
func EnsureClone(ctx context.Context, cacheDir, fullName, cloneURL string) (string, error) {
	dir := filepath.Join(cacheDir, strings.ReplaceAll(fullName, "/", "__")+".git")

	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil {
		return dir, nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	_ = os.RemoveAll(dir)

	if cloneURL == "" {
		cloneURL = "https://github.com/" + fullName + ".git"
	}
	if err := Clone(ctx, cloneURL, dir); err != nil {
		return "", err
	}
	if err := FetchPullRefs(ctx, dir); err != nil {
		// PR refs are best-effort; the named commit may well be on a branch.
		_ = err
	}
	return dir, nil
}

// Show renders a commit.
//
// This is the inspect half of the workflow, and the point at which blobs are
// finally pulled: the clone is a promisor, so git fetches exactly the objects
// this diff needs and nothing else. Rename detection is enabled here because
// content is being downloaded anyway.
func Show(ctx context.Context, dir, sha string, statOnly bool) (string, error) {
	args := []string{"show", "--find-renames", "--no-color"}
	if statOnly {
		args = append(args, "--stat")
	} else {
		args = append(args, "--patch")
	}
	args = append(args, sha, "--")

	out, err := run(ctx, dir, args...)
	if err != nil {
		return "", fmt.Errorf("show %s: %w", shortSHA(sha), err)
	}
	return out, nil
}

// ShowFile prints one file's content at a given commit, for pulling a single
// suspicious blob without materialising the whole diff.
func ShowFile(ctx context.Context, dir, sha, path string) (string, error) {
	return run(ctx, dir, "show", sha+":"+path)
}

func shortSHA(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
