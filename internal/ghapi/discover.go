package ghapi

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"skarvel/internal/model"
)

// Source labels where a candidate repo came from.
const (
	SourceSearch = "search"
	SourceOwned  = "owned"
	SourceEvents = "events"
	SourceOrgs   = "orgs"
)

// DiscoverOptions tunes the discovery phase.
type DiscoverOptions struct {
	// IncludeOrgs enumerates every public repo of every org the user publicly
	// belongs to. This is the only way to reach a repo the user touched solely
	// on a side branch, since commit search indexes default branches only --
	// but a large org can contribute thousands of repos with no evidence the
	// user ever touched them, so it is off by default.
	IncludeOrgs bool
	// IncludeForks keeps forked repos in the candidate set.
	IncludeForks bool
	// Since bounds the commit search; zero means from account creation.
	Since time.Time
}

// DiscoverResult is the output of the discovery phase.
type DiscoverResult struct {
	Identity  *model.Identity
	Repos     []model.Repo
	Truncated bool     // some search slice exceeded the 1000-result ceiling
	Notes     []string // human-readable caveats worth surfacing
}

type ghUser struct {
	Login     string    `json:"login"`
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type ghRepo struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Fork          bool   `json:"fork"`
	Private       bool   `json:"private"`
	Parent        *struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
}

type searchCommitsResp struct {
	TotalCount        int  `json:"total_count"`
	IncompleteResults bool `json:"incomplete_results"`
	Items             []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Author struct {
				Name  string    `json:"name"`
				Email string    `json:"email"`
				Date  time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
		Author *struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		} `json:"author"`
		Repository ghRepo `json:"repository"`
	} `json:"items"`
}

type ghEvent struct {
	Type string `json:"type"`
	Repo struct {
		Name string `json:"name"` // "owner/repo"
	} `json:"repo"`
}

// discoverer accumulates state across the discovery sources.
type discoverer struct {
	c     *Client
	login string
	opts  DiscoverOptions
	id    *model.Identity
	repos map[string]*model.Repo
	notes []string
	trunc bool
}

// Discover finds every public repository the login plausibly pushed code to,
// and harvests the commit emails GitHub attributes to that login.
//
// Discovery deliberately runs repo-first only as a supplement: the primary
// path is commit-first (search), because repo membership is not reliably
// visible for accounts you do not administer.
func (c *Client) Discover(ctx context.Context, login string, opts DiscoverOptions) (*DiscoverResult, error) {
	d := &discoverer{
		c:     c,
		login: login,
		opts:  opts,
		id:    model.NewIdentity(login),
		repos: map[string]*model.Repo{},
	}

	user, err := d.fetchUser(ctx)
	if err != nil {
		return nil, err
	}
	d.id.UserID = user.ID
	if user.Name != "" {
		d.id.AddName(user.Name)
	}

	since := opts.Since
	if since.IsZero() {
		since = user.CreatedAt
	}
	if since.IsZero() {
		since = time.Date(2008, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	// Order matters only for the notes; each source is independent.
	if err := d.searchCommits(ctx, since, time.Now().UTC(), 0); err != nil {
		return nil, fmt.Errorf("commit search: %w", err)
	}
	if err := d.ownedRepos(ctx); err != nil {
		return nil, fmt.Errorf("owned repos: %w", err)
	}
	if err := d.eventRepos(ctx); err != nil {
		// Events are a bonus source; a failure here should not sink the hunt.
		d.notes = append(d.notes, "events lookup failed: "+err.Error())
	}
	if opts.IncludeOrgs {
		if err := d.orgRepos(ctx); err != nil {
			d.notes = append(d.notes, "org enumeration failed: "+err.Error())
		}
	} else {
		d.notes = append(d.notes,
			"org repos not enumerated (--orgs); a repo touched only on a side branch of an org repo may be missed")
	}

	out := make([]model.Repo, 0, len(d.repos))
	for _, r := range d.repos {
		if r.IsFork && !opts.IncludeForks {
			continue
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })

	return &DiscoverResult{
		Identity:  d.id,
		Repos:     out,
		Truncated: d.trunc,
		Notes:     d.notes,
	}, nil
}

func (d *discoverer) fetchUser(ctx context.Context) (*ghUser, error) {
	var u ghUser
	_, err := d.c.getJSON(ctx, d.c.baseURL+"/users/"+url.PathEscape(d.login), &u)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("user %q not found", d.login)
	}
	if err != nil {
		return nil, err
	}
	// Preserve GitHub's canonical casing for the login.
	if u.Login != "" {
		d.login = u.Login
		d.id.Login = u.Login
		d.id.AddName(u.Login)
	}
	return &u, nil
}

// addRepo records a candidate, merging discovery sources when already present.
func (d *discoverer) addRepo(r ghRepo, source string) {
	full := r.FullName
	if full == "" || r.Private {
		return
	}
	owner, name, ok := strings.Cut(full, "/")
	if !ok {
		return
	}
	if r.Owner.Login != "" {
		owner = r.Owner.Login
	}
	if r.Name != "" {
		name = r.Name
	}

	existing, seen := d.repos[full]
	if !seen {
		existing = &model.Repo{
			FullName:      full,
			Owner:         owner,
			Name:          name,
			DiscoveredVia: source,
			Status:        model.StatusPending,
		}
		d.repos[full] = existing
	} else if !strings.Contains(existing.DiscoveredVia, source) {
		existing.DiscoveredVia += "," + source
	}

	// Later sources fill in fields earlier ones lacked; the search endpoint
	// returns a trimmed repository object.
	if existing.CloneURL == "" {
		existing.CloneURL = r.CloneURL
	}
	if existing.DefaultBranch == "" {
		existing.DefaultBranch = r.DefaultBranch
	}
	if r.Fork {
		existing.IsFork = true
	}
	if r.Parent != nil && existing.Parent == "" {
		existing.Parent = r.Parent.FullName
	}
	if existing.CloneURL == "" {
		existing.CloneURL = "https://github.com/" + full + ".git"
	}
}

// searchCommits walks GitHub's commit search, recursively halving the date
// range whenever a slice exceeds the API's hard 1000-result ceiling.
//
// This endpoint indexes default branches only. Its job here is to find repos
// and confirm which emails belong to the login; the local clone is what
// actually enumerates side branches.
func (d *discoverer) searchCommits(ctx context.Context, from, to time.Time, depth int) error {
	const (
		resultCeiling = 1000
		perPage       = 100
		maxDepth      = 12
	)

	q := fmt.Sprintf("author:%s author-date:%s..%s",
		d.login, from.Format("2006-01-02"), to.Format("2006-01-02"))
	base := fmt.Sprintf("%s/search/commits?q=%s&sort=author-date&order=asc&per_page=%d",
		d.c.baseURL, url.QueryEscape(q), perPage)

	var first searchCommitsResp
	if _, err := d.c.getSearch(ctx, base+"&page=1", &first); err != nil {
		return err
	}
	d.ingestSearch(&first)

	if first.TotalCount > resultCeiling {
		span := to.Sub(from)
		if span > 48*time.Hour && depth < maxDepth {
			mid := from.Add(span / 2)
			if err := d.searchCommits(ctx, from, mid, depth+1); err != nil {
				return err
			}
			return d.searchCommits(ctx, mid.AddDate(0, 0, 1), to, depth+1)
		}
		d.trunc = true
		d.notes = append(d.notes, fmt.Sprintf(
			"commit search hit the 1000-result ceiling for %s..%s (%d total); some default-branch commits were not seen during discovery",
			from.Format("2006-01-02"), to.Format("2006-01-02"), first.TotalCount))
	}

	// The API stops serving results past 1000 regardless of total_count.
	pages := (min(first.TotalCount, resultCeiling) + perPage - 1) / perPage
	for page := 2; page <= pages; page++ {
		var resp searchCommitsResp
		if _, err := d.c.getSearch(ctx, fmt.Sprintf("%s&page=%d", base, page), &resp); err != nil {
			return err
		}
		if len(resp.Items) == 0 {
			break
		}
		d.ingestSearch(&resp)
	}
	return nil
}

// ingestSearch records repos from search hits and, crucially, harvests the
// commit emails GitHub itself attributes to this login. Those emails are the
// bridge between the API's username-based view and the local clone, which
// knows only names and addresses.
func (d *discoverer) ingestSearch(resp *searchCommitsResp) {
	for _, item := range resp.Items {
		d.addRepo(item.Repository, SourceSearch)
		if item.Author != nil && strings.EqualFold(item.Author.Login, d.login) {
			d.id.AddEmail(item.Commit.Author.Email)
			d.id.AddName(item.Commit.Author.Name)
		}
	}
}

func (d *discoverer) ownedRepos(ctx context.Context) error {
	u := fmt.Sprintf("%s/users/%s/repos?type=owner&per_page=100&sort=pushed",
		d.c.baseURL, url.PathEscape(d.login))
	return d.c.paginate(ctx, u,
		func() any { return &[]ghRepo{} },
		func(page any) bool {
			for _, r := range *page.(*[]ghRepo) {
				d.addRepo(r, SourceOwned)
			}
			return true
		})
}

// eventRepos mines the public event feed. It reaches back only ~90 days and
// ~300 events, but unlike search it sees pushes to non-default branches, so it
// can surface a repo nothing else would.
func (d *discoverer) eventRepos(ctx context.Context) error {
	u := fmt.Sprintf("%s/users/%s/events/public?per_page=100", d.c.baseURL, url.PathEscape(d.login))
	return d.c.paginate(ctx, u,
		func() any { return &[]ghEvent{} },
		func(page any) bool {
			for _, e := range *page.(*[]ghEvent) {
				switch e.Type {
				// Code-bearing events only: the hunt is about pushed code, so
				// issue and review activity is deliberately ignored.
				case "PushEvent", "CreateEvent", "PullRequestEvent", "ForkEvent":
					if e.Repo.Name != "" {
						d.addRepo(ghRepo{FullName: e.Repo.Name}, SourceEvents)
					}
				}
			}
			return true
		})
}

// ListRepos returns every public repo owned by a login.
//
// The /users/{login}/repos endpoint serves organisations as well as personal
// accounts, so one call covers both without knowing which it is.
func (c *Client) ListRepos(ctx context.Context, owner string) ([]model.Repo, error) {
	var out []model.Repo
	u := fmt.Sprintf("%s/users/%s/repos?per_page=100&sort=pushed", c.baseURL, url.PathEscape(owner))

	err := c.paginate(ctx, u,
		func() any { return &[]ghRepo{} },
		func(page any) bool {
			for _, r := range *page.(*[]ghRepo) {
				if r.Private || r.FullName == "" {
					continue
				}
				o, n, _ := strings.Cut(r.FullName, "/")
				out = append(out, model.Repo{
					FullName:      r.FullName,
					Owner:         o,
					Name:          n,
					CloneURL:      r.CloneURL,
					DefaultBranch: r.DefaultBranch,
					IsFork:        r.Fork,
					DiscoveredVia: SourceOwned,
				})
			}
			return true
		})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out, nil
}

func (d *discoverer) orgRepos(ctx context.Context) error {
	var orgs []struct {
		Login string `json:"login"`
	}
	if _, err := d.c.getJSON(ctx,
		fmt.Sprintf("%s/users/%s/orgs?per_page=100", d.c.baseURL, url.PathEscape(d.login)), &orgs); err != nil {
		return err
	}
	for _, o := range orgs {
		u := fmt.Sprintf("%s/orgs/%s/repos?type=public&per_page=100", d.c.baseURL, url.PathEscape(o.Login))
		err := d.c.paginate(ctx, u,
			func() any { return &[]ghRepo{} },
			func(page any) bool {
				for _, r := range *page.(*[]ghRepo) {
					d.addRepo(r, SourceOrgs)
				}
				return true
			})
		if err != nil {
			d.notes = append(d.notes, fmt.Sprintf("org %s: %v", o.Login, err))
		}
	}
	return nil
}
