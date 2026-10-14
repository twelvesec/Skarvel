package gitx

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

// hostileRepo builds a repository whose contents are chosen to hurt a naive
// `cat-file --batch` reader:
//
//   - a file whose NAME contains a newline (git allows it), which would split
//     one request into two and shift every later response onto the wrong key;
//   - a blob larger than the size limit, sitting between ordinary files so a
//     reader that mishandles skipping goes out of step afterwards.
//
// Files sort as: a.txt, b.txt, big.txt, "x\nfake.txt".
func hostileRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	script := `set -e
git init -q -b main .
git config user.name t; git config user.email t@t
printf 'AAAA\n' > a.txt
printf 'BBBB\n' > b.txt
head -c 200000 /dev/zero | tr '\0' 'x' > big.txt
printf 'evil payload\n' > "$(printf 'x\nfake.txt')"
git add -A && git commit -qm fixture
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, out)
	}
	return dir
}

func blobsByPath(t *testing.T, dir string) (oids, paths []string) {
	t.Helper()
	tree, err := ListBlobs(context.Background(), dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range tree {
		oids = append(oids, b.OID)
		paths = append(paths, b.Path)
	}
	if len(paths) != 4 {
		t.Fatalf("fixture has %d files, want 4: %q", len(paths), paths)
	}
	return oids, paths
}

// Contents must come back attached to the right path -- including the path that
// contains a newline -- and the oversized blob must be skipped, not returned.
func TestCatBlobsAttributesContentToTheRightPath(t *testing.T) {
	dir := hostileRepo(t)
	oids, paths := blobsByPath(t, dir)

	got := map[string]string{}
	err := CatBlobs(context.Background(), dir, oids, 1000, func(i int, b Blob) error {
		got[paths[i]] = string(b.Data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"a.txt":       "AAAA\n",
		"b.txt":       "BBBB\n",
		"x\nfake.txt": "evil payload\n",
	}
	for p, c := range want {
		if got[p] != c {
			t.Errorf("content of %q = %q, want %q", p, got[p], c)
		}
	}
	if _, ok := got["big.txt"]; ok {
		t.Error("a blob over the size limit must be skipped, not delivered")
	}
	if len(got) != len(want) {
		t.Errorf("got %d blobs (%v), want %d", len(got), got, len(want))
	}
}

// The old spec-based reader paired responses to requests by position, so a
// newline in a path shifted everything after it. Such a spec is now refused and
// the rest still resolve correctly.
func TestCatFilesIgnoresSpecsThatWouldDesync(t *testing.T) {
	dir := hostileRepo(t)

	specs := []string{"main:a.txt", "main:x\nfake.txt", "main:b.txt"}
	got, err := CatFiles(context.Background(), dir, specs)
	if err != nil {
		t.Fatal(err)
	}
	if string(got["main:a.txt"].Data) != "AAAA\n" || string(got["main:b.txt"].Data) != "BBBB\n" {
		t.Errorf("later specs were misattributed: %v", got)
	}
	if _, ok := got["main:x\nfake.txt"]; ok {
		t.Error("a spec containing a newline must not be sent to git")
	}
}

// A malformed object ID is dropped without disturbing the others' indexes.
func TestCatBlobsIgnoresMalformedIDs(t *testing.T) {
	dir := hostileRepo(t)
	oids, _ := blobsByPath(t, dir)

	var seen []int
	err := CatBlobs(context.Background(), dir, []string{"HEAD:a.txt\nx", oids[0], "zz"}, 0,
		func(i int, b Blob) error {
			seen = append(seen, i)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != 1 {
		t.Errorf("callback indexes = %v, want [1]", seen)
	}
}

// An error from the callback (the analyzer returns its context error there)
// must stop the read and come back to the caller.
func TestCatBlobsStopsOnCallbackError(t *testing.T) {
	dir := hostileRepo(t)
	oids, _ := blobsByPath(t, dir)

	stop := errors.New("stop")
	calls := 0
	err := CatBlobs(context.Background(), dir, oids, 0, func(int, Blob) error {
		calls++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want the callback's error", err)
	}
	if calls != 1 {
		t.Errorf("callback ran %d times after returning an error", calls)
	}
}

func TestCatBlobsHonoursCancelledContext(t *testing.T) {
	dir := hostileRepo(t)
	oids, _ := blobsByPath(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CatBlobs(ctx, dir, oids, 0, func(int, Blob) error { return nil }); err == nil {
		t.Error("a cancelled context must not report success")
	}
}
