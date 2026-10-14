package gitx

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"skarvel/internal/model"
)

// fixture builds a repository exercising the cases extraction must get right:
// an on-default commit, a commit on a branch that was merged, a commit on a
// branch that never merged, a merge commit, a same-person-different-email
// commit, and an unrelated author's commit.
func fixture(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()

	script := `
set -e
git init -q -b main .
git config user.name "Target User"
git config user.email "1234+target@users.noreply.github.com"
git config commit.gpgsign false

echo a > a.txt
mkdir -p src && echo x > src/main.go
git add -A && git commit -qm "first commit"

# A branch that later gets merged: its commits ARE on the default branch.
git checkout -q -b merged-branch
echo y > src/helper.go
git add -A && git commit -qm "helper on merged branch"
git checkout -q main
git merge -q --no-ff merged-branch -m "merge merged-branch"

# A branch that is never merged: the primary triage target.
git checkout -q -b lurking
echo evil > src/backdoor.go
printf 'x\n' > "odd	name.txt"
git add -A && git commit -qm "add backdoor, never merged"
git rm -q a.txt && git commit -qm "delete a.txt on lurking"

# Same person, a different (non-noreply) email that discovery would have found.
git checkout -q main
git config user.email "target@personal.example"
echo z >> src/main.go
git add -A && git commit -qm "second on main under personal email"

# An unrelated author must never be attributed to the target.
git config user.name "Other Person"
git config user.email "other@example.com"
echo c > c.txt
git add -A && git commit -qm "not our commit"

# The target commits someone else's work: committer-only attribution.
git config user.name "Third Party"
git config user.email "third@example.com"
echo d > d.txt
git add -A
GIT_COMMITTER_NAME="Target User" \
GIT_COMMITTER_EMAIL="1234+target@users.noreply.github.com" \
  git commit -qm "authored by third party, landed by target"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture setup failed: %v\n%s", err, out)
	}
	return dir
}

func targetIdentity() *model.Identity {
	id := model.NewIdentity("target")
	id.AddEmail("target@personal.example") // as discovery would have supplied
	id.AddName("Target User")
	return id
}

func extract(t *testing.T, dir string, opts Options) map[string]model.Commit {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := Extract(ctx, dir, "acme/widget", targetIdentity(), opts)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	bySubject := map[string]model.Commit{}
	for _, c := range res.Commits {
		bySubject[c.Subject] = c
	}
	return bySubject
}

func TestExtractAttributesAndExcludes(t *testing.T) {
	got := extract(t, fixture(t), Options{IncludeCommitter: true})

	for _, want := range []string{
		"first commit",
		"helper on merged branch",
		"add backdoor, never merged",
		"delete a.txt on lurking",
		"second on main under personal email",
		"authored by third party, landed by target",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected commit %q to be attributed, but it was not", want)
		}
	}

	if _, ok := got["not our commit"]; ok {
		t.Error("commit by an unrelated author was wrongly attributed to the target")
	}
}

func TestOffDefaultDetection(t *testing.T) {
	got := extract(t, fixture(t), Options{IncludeCommitter: true})

	// Merged branch commits are reachable from the default branch, so they are
	// NOT off-default even though they were authored on a side branch.
	if c := got["helper on merged branch"]; c.OffDefault {
		t.Error("commit on a merged branch should not be flagged off-default")
	}
	if c := got["first commit"]; c.OffDefault {
		t.Error("root commit on the default branch should not be flagged off-default")
	}

	// The unmerged branch is exactly what the tool exists to surface.
	for _, subj := range []string{"add backdoor, never merged", "delete a.txt on lurking"} {
		c, ok := got[subj]
		if !ok {
			t.Fatalf("missing commit %q", subj)
		}
		if !c.OffDefault {
			t.Errorf("commit %q is on an unmerged branch and must be flagged off-default", subj)
		}
		if c.RefKind != model.RefBranch {
			t.Errorf("commit %q: got ref kind %q, want %q", subj, c.RefKind, model.RefBranch)
		}
	}
}

func TestConfidenceLevels(t *testing.T) {
	got := extract(t, fixture(t), Options{IncludeCommitter: true})

	cases := map[string]model.Confidence{
		// Discovery supplied this address, so it is a confirmed match.
		"second on main under personal email": model.ConfVerified,
		// Matched only by the GitHub noreply pattern.
		"first commit": model.ConfNoreply,
		// Authored by someone else, landed by the target.
		"authored by third party, landed by target": model.ConfCommitterOnly,
	}
	for subj, want := range cases {
		c, ok := got[subj]
		if !ok {
			t.Fatalf("missing commit %q", subj)
		}
		if c.Confidence != want {
			t.Errorf("commit %q: got confidence %q, want %q", subj, c.Confidence, want)
		}
	}
}

func TestCommitterPassIsOptional(t *testing.T) {
	got := extract(t, fixture(t), Options{IncludeCommitter: false})
	if _, ok := got["authored by third party, landed by target"]; ok {
		t.Error("committer-only commit should be absent when IncludeCommitter is false")
	}
	if _, ok := got["first commit"]; !ok {
		t.Error("authored commits must still be found without the committer pass")
	}
}

func TestFileListsAndStatuses(t *testing.T) {
	got := extract(t, fixture(t), Options{IncludeCommitter: true})

	backdoor := got["add backdoor, never merged"]
	paths := map[string]string{}
	for _, f := range backdoor.Files {
		paths[f.Path] = f.Status
	}
	if paths["src/backdoor.go"] != "A" {
		t.Errorf("src/backdoor.go: got status %q, want A", paths["src/backdoor.go"])
	}
	// A path containing a tab is quoted by git; unquoting must recover it,
	// otherwise record parsing would silently mangle the filename.
	if _, ok := paths["odd\tname.txt"]; !ok {
		t.Errorf("tab-containing path not unquoted correctly; got paths %v", paths)
	}

	del := got["delete a.txt on lurking"]
	if len(del.Files) != 1 || del.Files[0].Status != "D" || del.Files[0].Path != "a.txt" {
		t.Errorf("expected a single deletion of a.txt, got %+v", del.Files)
	}
}

func TestMergeCommitsCarryNoFiles(t *testing.T) {
	got := extract(t, fixture(t), Options{IncludeCommitter: true})

	m, ok := got["merge merged-branch"]
	if !ok {
		t.Fatal("merge commit was not attributed")
	}
	if !m.IsMerge || m.Parents != 2 {
		t.Errorf("merge commit misparsed: IsMerge=%v Parents=%d", m.IsMerge, m.Parents)
	}
	// A merge diff would attribute the whole merged branch to whoever pressed
	// the button, so the file list is deliberately empty.
	if len(m.Files) != 0 {
		t.Errorf("merge commit should carry no files, got %d", len(m.Files))
	}
}

func TestUnquotePath(t *testing.T) {
	cases := map[string]string{
		`plain.txt`:            `plain.txt`,
		`"with\tspace.txt"`:    "with\tspace.txt",
		`"line\nbreak.txt"`:    "line\nbreak.txt",
		`"quote\"inside.txt"`:  `quote"inside.txt`,
		`"back\\slash.txt"`:    `back\slash.txt`,
		`"caf\303\251.txt"`:    "café.txt",
		`no "quotes" here.txt`: `no "quotes" here.txt`,
	}
	for in, want := range cases {
		if got := unquotePath(in); got != want {
			t.Errorf("unquotePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentityRegexEscapesMetacharacters(t *testing.T) {
	id := model.NewIdentity("some.user")
	id.AddEmail("a+b@example.com")

	re := identityRegex(id)
	for _, want := range []string{`a\+b@example\.com`, `some\.user`} {
		if !strings.Contains(re, want) {
			t.Errorf("regex %q missing escaped alternative %q", re, want)
		}
	}
}

func TestIsTransientNetwork(t *testing.T) {
	transient := []string{
		"git clone: fatal: unable to access 'https://github.com/a/b.git/': Could not resolve host: github.com",
		"fatal: unable to access '...': Failed to connect to github.com port 443",
		"error: RPC failed; curl 56 Recv failure: Connection reset by peer",
		"fatal: the remote end hung up unexpectedly",
		"fatal: early EOF",
	}
	permanent := []string{
		"remote: Repository not found.",
		"fatal: Authentication failed",
		"fatal: destination path already exists",
		"remote: This repository has been disabled due to a DMCA takedown",
	}
	for _, s := range transient {
		if !isTransientNetwork(errors.New(s)) {
			t.Errorf("should retry: %q", s)
		}
	}
	for _, s := range permanent {
		if isTransientNetwork(errors.New(s)) {
			t.Errorf("must NOT retry (it is a real answer about the repo): %q", s)
		}
	}
}
