package gitx

import (
	"context"
	"os"
	"testing"
	"time"

	"skarvel/internal/model"
)

// TestAgainstRealRepo exercises the whole offline half of the pipeline --
// blobless clone, pull-ref fetch, and extraction -- against a real GitHub
// repository. Cloning public repos needs no authentication, so this runs
// without a token, but it does need network and is therefore opt-in.
//
//	SKARVEL_NET_TEST=1 go test ./internal/gitx/ -run RealRepo -v
func TestAgainstRealRepo(t *testing.T) {
	if os.Getenv("SKARVEL_NET_TEST") != "1" {
		t.Skip("set SKARVEL_NET_TEST=1 to run network integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	dir := t.TempDir() + "/hello.git"
	if err := Clone(ctx, "https://github.com/octocat/Hello-World.git", dir); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := FetchPullRefs(ctx, dir); err != nil {
		t.Fatalf("FetchPullRefs: %v", err)
	}

	branches, pulls := CountRefs(ctx, dir)
	t.Logf("refs: %d branches, %d pull refs", branches, pulls)
	if pulls == 0 {
		t.Error("expected pull refs to be fetched; unmerged PR code is the point of this step")
	}

	def, err := DefaultBranch(ctx, dir)
	if err != nil {
		t.Fatalf("DefaultBranch: %v", err)
	}
	t.Logf("default branch resolved from the clone: %s", def)

	id := model.NewIdentity("octocat")
	id.AddName("The Octocat")

	res, err := Extract(ctx, dir, "octocat/Hello-World", id, Options{IncludeCommitter: true})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(res.Commits) == 0 {
		t.Fatal("expected at least one attributed commit")
	}

	var off int
	for _, c := range res.Commits {
		if c.OffDefault {
			off++
		}
	}
	t.Logf("attributed %d commits (%d off-default)", len(res.Commits), off)
	for i, c := range res.Commits {
		if i >= 5 {
			break
		}
		t.Logf("  %s %-10s off=%-5v %-22s %s",
			c.SHA[:8], c.Confidence, c.OffDefault, c.SourceRef, c.Subject)
	}
}
