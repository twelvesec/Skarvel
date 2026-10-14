// Package model defines the core types shared across skarvel.
package model

import (
	"strings"
	"time"
)

// Confidence records how strongly a commit is attributed to the target user.
//
// A git commit carries only an author name and email; neither is authenticated,
// and neither contains a GitHub username. Attribution is therefore a judgement
// call, and skarvel records which evidence supported it rather than silently
// including or dropping borderline commits.
type Confidence string

const (
	// ConfVerified means the commit email appeared in a commit the GitHub API
	// attributed to this login. Strongest available signal.
	ConfVerified Confidence = "verified"
	// ConfNoreply means the email matches GitHub's noreply form for this
	// login, e.g. 1234567+octocat@users.noreply.github.com.
	ConfNoreply Confidence = "noreply"
	// ConfNameOnly means the author name matches but the email is unknown to
	// us. Weak, and the bucket where spoofing and throwaway addresses land --
	// which for threat hunting is a signal, not noise.
	ConfNameOnly Confidence = "name_only"
	// ConfCommitterOnly means the target is the committer but not the author,
	// e.g. they applied someone else's patch or landed a rebase.
	ConfCommitterOnly Confidence = "committer_only"
)

// Rank orders confidence levels for threshold filtering. Higher is stronger.
func (c Confidence) Rank() int {
	switch c {
	case ConfVerified:
		return 3
	case ConfNoreply:
		return 2
	case ConfNameOnly:
		return 1
	case ConfCommitterOnly:
		return 0
	}
	return -1
}

// ParseConfidence maps a user-supplied string to a Confidence.
func ParseConfidence(s string) (Confidence, bool) {
	switch Confidence(strings.ToLower(strings.TrimSpace(s))) {
	case ConfVerified:
		return ConfVerified, true
	case ConfNoreply:
		return ConfNoreply, true
	case ConfNameOnly:
		return ConfNameOnly, true
	case ConfCommitterOnly:
		return ConfCommitterOnly, true
	}
	return "", false
}

// RefKind classifies the ref that git traversal reached a commit through.
type RefKind string

const (
	RefDefault RefKind = "default" // the repo's default branch
	RefBranch  RefKind = "branch"  // some other branch
	RefPull    RefKind = "pull"    // refs/pull/N -- includes unmerged and rejected PRs
	RefTag     RefKind = "tag"
	RefOther   RefKind = "other"
)

// ClassifyRef maps a git ref name to a RefKind.
func ClassifyRef(ref, defaultBranch string) RefKind {
	switch {
	case ref == "":
		return RefOther
	case strings.HasPrefix(ref, "refs/pull/"):
		return RefPull
	case strings.HasPrefix(ref, "refs/tags/"):
		return RefTag
	case ref == defaultBranch ||
		ref == "refs/heads/"+defaultBranch ||
		ref == "refs/remotes/origin/"+defaultBranch:
		return RefDefault
	case strings.HasPrefix(ref, "refs/heads/"), strings.HasPrefix(ref, "refs/remotes/"):
		return RefBranch
	}
	return RefOther
}

// Repo is a candidate repository discovered through the GitHub API.
type Repo struct {
	FullName      string `json:"full_name"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	IsFork        bool   `json:"is_fork"`
	Parent        string `json:"parent,omitempty"`
	// DiscoveredVia lists the discovery sources that surfaced this repo,
	// comma-separated (search, owned, events, orgs).
	DiscoveredVia string     `json:"discovered_via"`
	Status        RepoStatus `json:"status"`
	Error         string     `json:"error,omitempty"`
	CommitsFound  int        `json:"commits_found"`
}

// RepoStatus tracks per-repo progress so interrupted runs can resume.
type RepoStatus string

const (
	StatusPending   RepoStatus = "pending"
	StatusExtracted RepoStatus = "extracted"
	StatusFailed    RepoStatus = "failed"
	StatusSkipped   RepoStatus = "skipped"
)

// Commit is a single commit attributed to the target user, as extracted from a
// local blobless clone.
type Commit struct {
	SHA            string    `json:"sha"`
	Repo           string    `json:"repo"`
	AuthorName     string    `json:"author_name"`
	AuthorEmail    string    `json:"author_email"`
	AuthorDate     time.Time `json:"author_date"`
	CommitterName  string    `json:"committer_name"`
	CommitterEmail string    `json:"committer_email"`
	CommitDate     time.Time `json:"commit_date"`
	Subject        string    `json:"subject"`
	Parents        int       `json:"parents"`
	IsMerge        bool      `json:"is_merge"`
	// SourceRef is the ref git traversal reached this commit from (git log
	// --source / %S). One ref, not necessarily the only one containing it.
	SourceRef string  `json:"source_ref"`
	RefKind   RefKind `json:"ref_kind"`
	// OffDefault is true when the commit is not reachable from the repo's
	// default branch -- the primary triage signal.
	OffDefault bool         `json:"off_default"`
	Confidence Confidence   `json:"confidence"`
	Files      []CommitFile `json:"files,omitempty"`
}

// CommitFile is one path touched by a commit.
//
// Rename detection is deliberately off during triage: it requires content
// similarity scoring, which forces blob fetching and defeats the blobless
// clone. Renames therefore appear as a delete plus an add.
type CommitFile struct {
	Path    string `json:"path"`
	Status  string `json:"status"` // A, M, D, T, C, R, U
	OldPath string `json:"old_path,omitempty"`
}

// Identity is the resolved set of git author identities belonging to a login.
type Identity struct {
	Login  string          `json:"login"`
	UserID int64           `json:"user_id"`
	Emails map[string]bool `json:"emails"` // lowercased
	Names  map[string]bool `json:"names"`  // lowercased
}

// NewIdentity returns an Identity seeded with the login itself as a name
// candidate, since many users commit under their username.
func NewIdentity(login string) *Identity {
	id := &Identity{
		Login:  login,
		Emails: map[string]bool{},
		Names:  map[string]bool{},
	}
	id.AddName(login)
	return id
}

// AddEmail records a commit email belonging to this login.
func (i *Identity) AddEmail(e string) {
	e = strings.ToLower(strings.TrimSpace(e))
	if e != "" {
		i.Emails[e] = true
	}
}

// AddName records a commit author name belonging to this login.
func (i *Identity) AddName(n string) {
	n = strings.ToLower(strings.TrimSpace(n))
	if n != "" {
		i.Names[n] = true
	}
}

// IsNoreply reports whether an email is a GitHub noreply address for this
// login. Both the modern <id>+<login>@ and legacy <login>@ forms are accepted.
func (i *Identity) IsNoreply(email string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	const suffix = "@users.noreply.github.com"
	if !strings.HasSuffix(e, suffix) {
		return false
	}
	local := strings.TrimSuffix(e, suffix)
	if idx := strings.Index(local, "+"); idx >= 0 {
		local = local[idx+1:]
	}
	return local == strings.ToLower(i.Login)
}

// Classify attributes a commit to this identity, returning the strength of the
// match and whether it matched at all.
//
// Author fields are checked before committer fields: authorship is the claim
// about who wrote the code, which is what a hunt cares about.
func (i *Identity) Classify(authorName, authorEmail, committerName, committerEmail string) (Confidence, bool) {
	ae := strings.ToLower(strings.TrimSpace(authorEmail))
	an := strings.ToLower(strings.TrimSpace(authorName))

	if ae != "" && i.Emails[ae] {
		return ConfVerified, true
	}
	if i.IsNoreply(authorEmail) {
		return ConfNoreply, true
	}
	if an != "" && i.Names[an] {
		return ConfNameOnly, true
	}

	ce := strings.ToLower(strings.TrimSpace(committerEmail))
	cn := strings.ToLower(strings.TrimSpace(committerName))
	if (ce != "" && i.Emails[ce]) || i.IsNoreply(committerEmail) || (cn != "" && i.Names[cn]) {
		return ConfCommitterOnly, true
	}
	return "", false
}
