package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"skarvel/internal/gitx"
)

// gitRepo commits the given files into a fresh repository and returns its path.
func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "-A"},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "fixture"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// The scan command runs signatures through git grep -E, not Go's regexp, and
// the two dialects disagree: in POSIX ERE "[^\n]" excludes a backslash and the
// letter n, not a newline. TestSignaturesCompileAndMatch cannot see that, so
// every sample is also run through the engine scan actually uses.
func TestSignaturesMatchUnderGitGrep(t *testing.T) {
	files := map[string]string{"benign.txt": strings.Join(benignLines, "\n")}
	for name, sample := range signatureSamples {
		files[name+".txt"] = sample
	}
	dir := gitRepo(t, files)

	hits, err := contentScan(context.Background(), dir, Config{})
	if err != nil {
		t.Fatalf("contentScan: %v", err)
	}
	found := map[string]bool{}
	for _, h := range hits {
		if h.Path == "benign.txt" {
			t.Errorf("signature %q false-positives under git grep on: %s", h.Signature, h.Text)
		}
		found[h.Signature+"\x00"+h.Path] = true
	}
	for _, sig := range Signatures {
		if !found[sig.Name+"\x00"+sig.Name+".txt"] {
			t.Errorf("signature %q did not match its own sample under git grep", sig.Name)
		}
	}
}

// A pattern git cannot run must fail the scan, never read as "no hits".
func TestGrepFailureIsNotClean(t *testing.T) {
	dir := gitRepo(t, map[string]string{"a.txt": "hello"})
	revs, err := gitx.RefTips(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gitx.Grep(context.Background(), dir, "(unclosed", revs, 0); err == nil {
		t.Fatal("invalid pattern returned no error")
	}
	if hits, err := gitx.Grep(context.Background(), dir, "absent-string", revs, 0); err != nil || len(hits) != 0 {
		t.Fatalf("no-match grep = %v, %v; want no hits and no error", hits, err)
	}
}
