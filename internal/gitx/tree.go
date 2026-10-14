package gitx

import (
	"context"
	"strings"
)

// ListFiles returns every path in a revision's tree.
func ListFiles(ctx context.Context, dir, rev string) ([]string, error) {
	out, err := run(ctx, dir, "ls-tree", "-r", "--name-only", "-z", rev)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// PathAuthor is one identity that touched a path.
type PathAuthor struct {
	Name  string
	Email string
	SHA   string
}

// AuthorsOfPath returns the identities that committed changes to a path.
//
// This is how expansion follows authorship rather than ownership: a payload
// found at a path implicates whoever put it there, who is frequently not the
// repository's owner.
func AuthorsOfPath(ctx context.Context, dir, rev, path string, limit int) ([]PathAuthor, error) {
	args := []string{"log", "--format=%H\x1f%an\x1f%ae", "--no-merges"}
	if limit > 0 {
		args = append(args, "-n", itoa(limit))
	}
	args = append(args, rev, "--", path)

	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	var authors []PathAuthor
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) < 3 {
			continue
		}
		key := f[1] + "|" + f[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		authors = append(authors, PathAuthor{SHA: f[0], Name: f[1], Email: f[2]})
	}
	return authors, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TreeBlob is one file in a revision's tree, with its content ID.
type TreeBlob struct {
	Path string
	OID  string
}

// ListBlobs returns every file in a revision's tree together with its blob ID.
//
// The blob ID is what lets a multi-ref scan skip content it has already read
// without skipping a *different* version of a path it has seen: a side branch
// that rewrites .vscode/settings.json has the same path as the default branch
// but a different blob, and it is exactly the version worth reading.
func ListBlobs(ctx context.Context, dir, rev string) ([]TreeBlob, error) {
	out, err := run(ctx, dir, "ls-tree", "-r", "-z", "--full-tree", rev)
	if err != nil {
		return nil, err
	}
	var blobs []TreeBlob
	for _, rec := range strings.Split(out, "\x00") {
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok || path == "" {
			continue
		}
		f := strings.Fields(meta) // <mode> <type> <oid>
		if len(f) != 3 || f[1] != "blob" {
			continue
		}
		blobs = append(blobs, TreeBlob{Path: path, OID: f[2]})
	}
	return blobs, nil
}
