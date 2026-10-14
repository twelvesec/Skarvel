package gitx

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"skarvel/internal/model"
)

// Record and field separators embedded in the pretty format. Both are ASCII
// control characters that cannot appear in a commit header, so splitting on
// them is unambiguous.
const (
	recSep = "\x1e"
	fldSep = "\x1f"

	// %S emits the ref the traversal reached this commit through, and needs
	// --source to be set.
	prettyFormat = "--pretty=format:" + recSep +
		"%H" + fldSep + "%P" + fldSep +
		"%an" + fldSep + "%ae" + fldSep + "%aI" + fldSep +
		"%cn" + fldSep + "%ce" + fldSep + "%cI" + fldSep +
		"%S" + fldSep + "%s"
)

// Options tunes extraction.
type Options struct {
	// IncludeCommitter runs a second pass matching the committer fields, which
	// catches commits the target landed but did not author (applied patches,
	// rebases). Classified as ConfCommitterOnly.
	IncludeCommitter bool
}

// Result is the outcome of extracting one repository.
type Result struct {
	Commits       []model.Commit
	DefaultBranch string
	Branches      int
	Pulls         int
}

// Extract walks every ref in the clone and returns the commits attributable to
// the identity, each tagged with its confidence and whether it is reachable
// from the default branch.
func Extract(ctx context.Context, dir, repoFullName string, id *model.Identity, opts Options) (*Result, error) {
	res := &Result{}

	if IsEmpty(ctx, dir) {
		return res, nil
	}
	def, err := DefaultBranch(ctx, dir)
	if err != nil {
		// A clone whose HEAD is unresolvable still has refs worth walking; we
		// just cannot distinguish on- from off-default, so treat all as off.
		def = ""
	}
	res.DefaultBranch = def
	res.Branches, res.Pulls = CountRefs(ctx, dir)

	re := identityRegex(id)
	if re == "" {
		return res, nil
	}

	// Each filter kind needs its own invocation: git ORs repeated --author
	// values among themselves, but ANDs --author with --committer.
	filters := []string{"--author"}
	if opts.IncludeCommitter {
		filters = append(filters, "--committer")
	}

	// The git-level regex is a deliberately loose prefilter -- it exists to
	// let git's C matcher discard the bulk of history cheaply. Precise
	// attribution happens in Go below, so over-matching here costs only time
	// and under-matching is what we must avoid.
	merged := map[string]*model.Commit{}
	for _, f := range filters {
		raw, err := logFull(ctx, dir, "--all", f, re)
		if err != nil {
			return nil, err
		}
		for _, c := range raw {
			if _, seen := merged[c.SHA]; !seen {
				cp := c
				merged[c.SHA] = &cp
			}
		}
	}

	// Off-default status comes from a separate, authoritative traversal of the
	// default branch rather than from %S, which reports only the one ref the
	// --all walk happened to arrive by.
	onDefault := map[string]bool{}
	if def != "" {
		for _, f := range filters {
			shas, err := logSHAs(ctx, dir, def, f, re)
			if err != nil {
				// The default ref may be missing in odd clones; degrade to
				// treating everything as off-default rather than failing.
				break
			}
			for s := range shas {
				onDefault[s] = true
			}
		}
	}

	for _, c := range merged {
		conf, ok := id.Classify(c.AuthorName, c.AuthorEmail, c.CommitterName, c.CommitterEmail)
		if !ok {
			// Matched git's loose prefilter but not our strict rules.
			continue
		}
		c.Repo = repoFullName
		c.Confidence = conf
		c.OffDefault = !onDefault[c.SHA]
		c.RefKind = model.ClassifyRef(c.SourceRef, def)
		if !c.OffDefault {
			c.RefKind = model.RefDefault
		}
		res.Commits = append(res.Commits, *c)
	}

	sort.Slice(res.Commits, func(i, j int) bool {
		if res.Commits[i].AuthorDate.Equal(res.Commits[j].AuthorDate) {
			return res.Commits[i].SHA < res.Commits[j].SHA
		}
		return res.Commits[i].AuthorDate.After(res.Commits[j].AuthorDate)
	})
	return res, nil
}

// logFull runs git log with per-commit file lists and parses the output.
func logFull(ctx context.Context, dir, rev, filterFlag, re string) ([]model.Commit, error) {
	args := []string{"log", rev, "--source", "--name-status",
		"--regexp-ignore-case", "--extended-regexp",
		filterFlag + "=" + re, prettyFormat}
	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	return parseLog(out), nil
}

// logSHAs runs the same filtered query but returns only commit hashes.
func logSHAs(ctx context.Context, dir, rev, filterFlag, re string) (map[string]bool, error) {
	args := []string{"log", rev,
		"--regexp-ignore-case", "--extended-regexp",
		filterFlag + "=" + re, "--pretty=format:%H"}
	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// parseLog turns raw git log output into commits.
//
// Merge commits carry no file list here by design: git omits diffs for merges
// unless explicitly asked, and a merge diff would otherwise attribute an
// entire feature branch to whoever pressed the merge button.
func parseLog(out string) []model.Commit {
	var commits []model.Commit

	for _, rec := range strings.Split(out, recSep) {
		if strings.TrimSpace(rec) == "" {
			continue
		}
		lines := strings.Split(rec, "\n")
		fields := strings.Split(lines[0], fldSep)
		if len(fields) < 10 {
			continue
		}

		parents := strings.Fields(fields[1])
		c := model.Commit{
			SHA:            fields[0],
			Parents:        len(parents),
			IsMerge:        len(parents) > 1,
			AuthorName:     fields[2],
			AuthorEmail:    fields[3],
			AuthorDate:     parseGitTime(fields[4]),
			CommitterName:  fields[5],
			CommitterEmail: fields[6],
			CommitDate:     parseGitTime(fields[7]),
			SourceRef:      fields[8],
			Subject:        fields[9],
		}

		for _, line := range lines[1:] {
			if line == "" {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) < 2 {
				continue
			}
			status := parts[0]
			f := model.CommitFile{Status: status}
			// Rename and copy entries carry both paths. We do not enable -M,
			// but git still reports pure renames it detects for free.
			if len(parts) >= 3 && (strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C")) {
				f.OldPath = unquotePath(parts[1])
				f.Path = unquotePath(parts[2])
			} else {
				f.Path = unquotePath(parts[1])
			}
			if f.Path != "" {
				c.Files = append(c.Files, f)
			}
		}
		commits = append(commits, c)
	}
	return commits
}

func parseGitTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// identityRegex builds an extended-regex alternation matching any known email
// or name, plus the GitHub noreply form for the login.
//
// git matches this against the full "Name <email>" ident string and the match
// is unanchored, so listing the bare noreply address also catches the numeric
// "<id>+login@users.noreply.github.com" variant.
func identityRegex(id *model.Identity) string {
	seen := map[string]bool{}
	var alts []string

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		alts = append(alts, quoteERE(s))
	}

	for e := range id.Emails {
		add(e)
	}
	for n := range id.Names {
		add(n)
	}
	add(strings.ToLower(id.Login) + "@users.noreply.github.com")

	sort.Strings(alts) // deterministic command lines aid debugging
	return strings.Join(alts, "|")
}

// quoteERE escapes POSIX extended-regex metacharacters.
func quoteERE(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, r := range s {
		if strings.ContainsRune(`.+*?()[]{}|^$\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unquotePath reverses git's C-style path quoting (core.quotePath), which is
// what keeps paths containing tabs or newlines from breaking record parsing.
func unquotePath(p string) string {
	if len(p) < 2 || p[0] != '"' || p[len(p)-1] != '"' {
		return p
	}
	inner := p[1 : len(p)-1]
	var b strings.Builder
	b.Grow(len(inner))

	for i := 0; i < len(inner); i++ {
		if inner[i] != '\\' || i+1 >= len(inner) {
			b.WriteByte(inner[i])
			continue
		}
		i++
		switch inner[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			// Octal escape \NNN, used for non-ASCII bytes.
			if i+2 < len(inner) {
				if n, err := strconv.ParseUint(inner[i:i+3], 8, 8); err == nil {
					b.WriteByte(byte(n))
					i += 2
					continue
				}
			}
			b.WriteByte(inner[i])
		}
	}
	return b.String()
}
