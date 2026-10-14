package criteria

import "testing"

func TestFindingURLPerHost(t *testing.T) {
	base := Finding{Repo: "acme/widget", Path: ".vscode/settings.json", Line: 1, SHA: "abc123"}

	gh := base
	if got, want := gh.URL(), "https://github.com/acme/widget/blob/abc123/.vscode/settings.json#L1"; got != want {
		t.Errorf("github url = %q, want %q", got, want)
	}

	bb := base
	bb.Host = HostBitbucket
	if got, want := bb.URL(), "https://bitbucket.org/acme/widget/src/abc123/.vscode/settings.json#lines-1"; got != want {
		t.Errorf("bitbucket url = %q, want %q", got, want)
	}

	repoOnly := Finding{Repo: "acme/widget", Host: HostBitbucket}
	if got, want := repoOnly.URL(), "https://bitbucket.org/acme/widget"; got != want {
		t.Errorf("bitbucket repo url = %q, want %q", got, want)
	}

	if got, want := RepoURL("", "acme/widget"), "https://github.com/acme/widget"; got != want {
		t.Errorf("default host url = %q, want %q", got, want)
	}
}
