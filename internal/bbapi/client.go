// Package bbapi is a minimal Bitbucket Cloud REST client that lets the crawler
// and the scanner run against bitbucket.org the way they run against GitHub.
//
// It satisfies crawl.Platform, so the expansion engine does not know which
// platform it is talking to. Three differences from GitHub shape the code:
//
//   - Code search is scoped to a workspace. Bitbucket has no global index, so
//     the client holds the list of workspaces to search and fans each query out
//     across them. A run that names no workspace cannot search at all.
//   - There is no cross-repository commit search, so identity expansion
//     (ReposForIdentity) is reported as unsupported rather than silently empty.
//   - Public data is readable anonymously. Credentials are optional and only
//     raise the rate limit (Bitbucket allows far fewer anonymous requests per
//     hour) or unlock private workspaces.
package bbapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"skarvel/internal/ghapi"
	"skarvel/internal/model"
)

const (
	defaultBaseURL = "https://api.bitbucket.org/2.0"
	webBase        = "https://bitbucket.org"
	userAgent      = "skarvel/0.1"
	maxRetries     = 5

	// Bitbucket search is noticeably slower than GitHub's and throttles bursts;
	// spacing queries keeps a run clear of 429s without reacting to them.
	searchInterval = 1500 * time.Millisecond
)

// ErrNotFound indicates a 404 from the API.
var ErrNotFound = errors.New("not found")

// ErrUnauthorized means Bitbucket rejected the configured credentials. Public
// data needs none, so a 401 is never "no access" -- it is always bad
// credentials, and every search made with them will fail the same way.
var ErrUnauthorized = errors.New("401 unauthorized: Bitbucket credentials are missing, expired, or malformed")

// ErrUnsupported marks a capability Bitbucket Cloud does not offer.
var ErrUnsupported = errors.New("not supported by Bitbucket Cloud")

// ErrNoWorkspace is returned by SearchCode when no workspace was configured.
var ErrNoWorkspace = errors.New("Bitbucket code search is workspace-scoped: pass --workspace <slug> (repeatable)")

// Auth carries optional credentials. Zero value means anonymous.
type Auth struct {
	// Token is a Bitbucket API token or OAuth access token, sent as Bearer.
	Token string
	// User and AppPassword are sent as HTTP Basic auth when Token is empty.
	User        string
	AppPassword string
}

// Client talks to the Bitbucket Cloud 2.0 API.
type Client struct {
	http       *http.Client
	baseURL    string
	auth       Auth
	workspaces []string

	searchMu   sync.Mutex
	lastSearch time.Time

	// Logf is a verbose logging sink; nil disables it.
	Logf func(format string, args ...any)
}

// New returns a client that searches the given workspaces.
func New(workspaces []string, auth Auth) *Client {
	return &Client{
		http:       &http.Client{Timeout: 45 * time.Second},
		baseURL:    defaultBaseURL,
		auth:       auth,
		workspaces: dedupe(workspaces),
	}
}

// AuthFromEnv reads BITBUCKET_TOKEN, or BITBUCKET_USER plus
// BITBUCKET_APP_PASSWORD, from the environment.
//
// An Atlassian account API token placed in BITBUCKET_TOKEN is moved to Basic
// auth when BITBUCKET_USER names the account: Bitbucket only accepts those
// tokens as email:token, and as a Bearer token every request would get 401.
func AuthFromEnv(getenv func(string) string) Auth {
	a := Auth{
		Token:       strings.TrimSpace(getenv("BITBUCKET_TOKEN")),
		User:        strings.TrimSpace(getenv("BITBUCKET_USER")),
		AppPassword: strings.TrimSpace(getenv("BITBUCKET_APP_PASSWORD")),
	}
	if IsAccountAPIToken(a.Token) && a.User != "" && a.AppPassword == "" {
		a.AppPassword, a.Token = a.Token, ""
	}
	return a
}

// IsAccountAPIToken reports whether tok looks like an Atlassian account API
// token (prefix ATATT), which is Basic-auth only, as opposed to a workspace or
// repository access token, which is sent as Bearer.
func IsAccountAPIToken(tok string) bool { return strings.HasPrefix(tok, "ATATT") }

// Authenticated reports whether any credential is configured.
func (a Auth) Authenticated() bool {
	return a.Token != "" || (a.User != "" && a.AppPassword != "")
}

// Workspaces returns the workspaces this client searches.
func (c *Client) Workspaces() []string { return append([]string(nil), c.workspaces...) }

// WorkspaceStatus is the preflight result for one workspace slug.
type WorkspaceStatus struct {
	Slug   string
	Exists bool   // false when Bitbucket reports no such workspace
	Repos  int    // public repositories visible with the current credentials
	Err    string // non-empty for failures other than "does not exist"
	// Unauthorized: Bitbucket rejected the credentials themselves.
	Unauthorized bool
}

// CheckWorkspaces verifies every configured workspace before a crawl starts.
//
// Bitbucket answers a search inside a missing workspace with the same 404 it
// uses for an empty one, so a run against a mistyped or never-registered slug
// would otherwise look like a clean sweep. Checking the repository listing
// first turns that into an explicit "does not exist" per slug. A workspace
// that exists but lists zero public repositories is reported, not rejected:
// its code may still be searchable with credentials.
func (c *Client) CheckWorkspaces(ctx context.Context) []WorkspaceStatus {
	out := make([]WorkspaceStatus, 0, len(c.workspaces))
	for _, ws := range c.workspaces {
		st := WorkspaceStatus{Slug: ws}
		var p page[struct{}]
		u := c.baseURL + "/repositories/" + url.PathEscape(ws) + "?pagelen=1&fields=size"
		switch err := c.getJSON(ctx, u, &p); {
		case err == nil:
			st.Exists = true
			st.Repos = p.Size
		case errors.Is(err, ErrNotFound):
			st.Exists = false
		case errors.Is(err, ErrUnauthorized):
			st.Exists, st.Unauthorized, st.Err = true, true, err.Error()
		default:
			st.Exists = true // unknown: a 403 or a network error is not absence
			st.Err = err.Error()
		}
		out = append(out, st)
	}
	return out
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(strings.Trim(s, "/"))
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	return out
}

// do issues a GET, retrying on throttling and transient failures.
func (c *Client) do(ctx context.Context, u string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		switch {
		case c.auth.Token != "":
			req.Header.Set("Authorization", "Bearer "+c.auth.Token)
		case c.auth.User != "" && c.auth.AppPassword != "":
			req.SetBasicAuth(c.auth.User, c.auth.AppPassword)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			if !sleepCtx(ctx, backoff(attempt)) {
				return nil, ctx.Err()
			}
			continue
		}

		switch {
		case resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			return nil, ErrNotFound

		case resp.StatusCode == http.StatusUnauthorized:
			// Bitbucket sometimes says why (for instance "API Token provided
			// has no Bitbucket scopes"); keep that, it is the actual fix.
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			var e struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
				return nil, fmt.Errorf("%w: Bitbucket says: %s", ErrUnauthorized, e.Error.Message)
			}
			return nil, ErrUnauthorized

		case resp.StatusCode == http.StatusForbidden:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("403 forbidden (private workspace, or search disabled for it): %s",
				strings.TrimSpace(string(body)))

		case resp.StatusCode == http.StatusTooManyRequests:
			resp.Body.Close()
			wait, quota := retryAfter(resp, attempt)
			// The anonymous quota is per hour. Sleeping it out would park the
			// run silently for longer than any sensible --max-time, so beyond a
			// short wait the honest answer is an error that names the fix.
			if wait > maxQuotaWait {
				return nil, fmt.Errorf("rate limited (%s): quota resets in %s; set BITBUCKET_TOKEN (or BITBUCKET_USER + BITBUCKET_APP_PASSWORD) for the authenticated limit",
					quota, wait.Round(time.Second))
			}
			c.logf("rate limited (%s), waiting %s", quota, wait.Round(time.Second))
			if !sleepCtx(ctx, wait) {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("rate limited: %s", resp.Status)
			continue

		case resp.StatusCode >= 500:
			resp.Body.Close()
			lastErr = fmt.Errorf("server error: %s", resp.Status)
			if !sleepCtx(ctx, backoff(attempt)) {
				return nil, ctx.Err()
			}
			continue

		case resp.StatusCode >= 400:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		return resp, nil
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", maxRetries, lastErr)
}

// maxQuotaWait is the longest a single throttled request is waited out before
// the client gives up and reports the quota instead.
const maxQuotaWait = 90 * time.Second

// retryAfter reads how long Bitbucket wants us to wait and which quota was
// hit. Bitbucket sends x-ratelimit-reset as seconds until the window resets
// and x-ratelimit-limit as "N, N;w=<window seconds>"; Retry-After is rare.
func retryAfter(resp *http.Response, attempt int) (wait time.Duration, quota string) {
	quota = "unknown quota"
	if lim := resp.Header.Get("x-ratelimit-limit"); lim != "" {
		n := strings.TrimSpace(strings.Split(lim, ",")[0])
		window := "hour"
		if i := strings.Index(lim, "w="); i >= 0 {
			if secs, err := strconv.Atoi(strings.TrimSpace(lim[i+2:])); err == nil {
				window = (time.Duration(secs) * time.Second).String()
			}
		}
		quota = n + " requests per " + window
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			return time.Duration(secs)*time.Second + time.Second, quota
		}
	}
	if rs := resp.Header.Get("x-ratelimit-reset"); rs != "" {
		if secs, err := strconv.Atoi(rs); err == nil && secs > 0 {
			return time.Duration(secs)*time.Second + time.Second, quota
		}
	}
	d := time.Duration(15<<attempt) * time.Second
	if d > maxQuotaWait {
		d = maxQuotaWait + time.Second
	}
	return d, quota
}

func backoff(attempt int) time.Duration {
	d := time.Second << attempt
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (c *Client) getJSON(ctx context.Context, u string, v any) error {
	resp, err := c.do(ctx, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

// page is the envelope every Bitbucket list endpoint uses.
type page[T any] struct {
	Size   int    `json:"size"`
	Next   string `json:"next"`
	Values []T    `json:"values"`
}

// paginate walks a list endpoint until fn returns false or pages run out.
func paginate[T any](ctx context.Context, c *Client, u string, fn func(T) bool) error {
	for u != "" {
		var p page[T]
		if err := c.getJSON(ctx, u, &p); err != nil {
			return err
		}
		for _, v := range p.Values {
			if !fn(v) {
				return nil
			}
		}
		u = p.Next
	}
	return nil
}

// repoJSON is the subset of the repository resource skarvel needs.
type repoJSON struct {
	FullName    string `json:"full_name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	IsPrivate   bool   `json:"is_private"`
	Size        int64  `json:"size"` // bytes
	CreatedOn   string `json:"created_on"`
	UpdatedOn   string `json:"updated_on"`
	MainBranch  *struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
	Parent *struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
	Owner struct {
		Nickname    string `json:"nickname"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Type        string `json:"type"`
	} `json:"owner"`
	Workspace struct {
		Slug string `json:"slug"`
	} `json:"workspace"`
	Links struct {
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
	} `json:"links"`
}

func (r repoJSON) httpsClone() string {
	for _, l := range r.Links.Clone {
		if l.Name == "https" {
			return l.Href
		}
	}
	return webBase + "/" + r.FullName + ".git"
}

// ListRepos returns every public repository in a workspace (or user account).
func (c *Client) ListRepos(ctx context.Context, owner string) ([]model.Repo, error) {
	u := c.baseURL + "/repositories/" + url.PathEscape(owner) + "?pagelen=100"
	var out []model.Repo
	err := paginate(ctx, c, u, func(r repoJSON) bool {
		if r.IsPrivate && !c.auth.Authenticated() {
			return true
		}
		m := model.Repo{
			FullName:      r.FullName,
			Owner:         owner,
			Name:          r.Slug,
			CloneURL:      r.httpsClone(),
			IsFork:        r.Parent != nil,
			DiscoveredVia: "owned",
		}
		if r.MainBranch != nil {
			m.DefaultBranch = r.MainBranch.Name
		}
		if r.Parent != nil {
			m.Parent = r.Parent.FullName
		}
		out = append(out, m)
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("list repositories of %s: %w", owner, err)
	}
	return out, nil
}

// GetRepo fetches repository metadata in the shape the engine's guards expect.
func (c *Client) GetRepo(ctx context.Context, fullName string) (*ghapi.RepoMeta, error) {
	var r repoJSON
	if err := c.getJSON(ctx, c.baseURL+"/repositories/"+fullName, &r); err != nil {
		return nil, err
	}
	m := &ghapi.RepoMeta{
		FullName:    r.FullName,
		Description: r.Description,
		Fork:        r.Parent != nil,
		Private:     r.IsPrivate,
		CloneURL:    r.httpsClone(),
		CreatedAt:   r.CreatedOn,
		PushedAt:    r.UpdatedOn,
		// GitHub reports kilobytes and the engine's clone limit is in KB.
		Size: int(r.Size / 1024),
	}
	m.Owner.Login = firstNonEmpty(r.Workspace.Slug, r.Owner.Nickname, r.Owner.Username, strings.Split(fullName, "/")[0])
	m.Owner.Type = r.Owner.Type
	if r.Parent != nil {
		m.Parent = &struct {
			FullName string `json:"full_name"`
		}{FullName: r.Parent.FullName}
	}
	return m, nil
}

// GetReadme returns the head of the README at the default branch, for the
// corpus classifier. A missing README is not an error.
func (c *Client) GetReadme(ctx context.Context, fullName string, maxBytes int) (string, error) {
	// One listing of the root tree finds the README under whatever case and
	// extension the project used; guessing names costs a request per miss.
	type entry struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	var readme string
	u := c.baseURL + "/repositories/" + fullName + "/src/HEAD/?pagelen=100&fields=next,values.path,values.type"
	_ = paginate(ctx, c, u, func(e entry) bool {
		if e.Type == "commit_file" && strings.HasPrefix(strings.ToLower(e.Path), "readme") {
			readme = e.Path
			return false
		}
		return true
	})
	if readme == "" {
		return "", nil
	}
	resp, err := c.do(ctx, c.baseURL+"/repositories/"+fullName+"/src/HEAD/"+url.PathEscape(readme))
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)))
	if err != nil {
		return "", nil
	}
	return string(b), nil
}

type searchResult struct {
	File struct {
		Path   string `json:"path"`
		Commit struct {
			Hash       string `json:"hash"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"commit"`
	} `json:"file"`
}

// SearchCode runs a code search across every configured workspace.
//
// The query arrives in GitHub syntax because the engine builds it. Bitbucket
// accepts quoted phrases unchanged; GitHub-only qualifiers are translated
// where Bitbucket has an equivalent (language: -> ext:) and dropped otherwise,
// so a query is never sent in a form the backend would silently misread.
func (c *Client) SearchCode(ctx context.Context, query string, maxPages int) (hits []ghapi.CodeHit, total int, err error) {
	if len(c.workspaces) == 0 {
		return nil, 0, ErrNoWorkspace
	}
	if maxPages <= 0 {
		maxPages = 1
	}
	q := translateQuery(query)

	var errs []string
	for _, ws := range c.workspaces {
		u := c.baseURL + "/workspaces/" + url.PathEscape(ws) + "/search/code?pagelen=100" +
			"&fields=size,next,values.file.path,values.file.commit.hash,values.file.commit.repository.full_name" +
			"&search_query=" + url.QueryEscape(q)
		for pg := 0; pg < maxPages && u != ""; pg++ {
			var p page[searchResult]
			if werr := c.getSearch(ctx, u, &p); werr != nil {
				if errors.Is(werr, ErrNotFound) {
					werr = fmt.Errorf("workspace %q not found or not searchable anonymously", ws)
				}
				errs = append(errs, werr.Error())
				break
			}
			if pg == 0 {
				total += p.Size
			}
			for _, r := range p.Values {
				full := r.File.Commit.Repository.FullName
				if full == "" {
					continue
				}
				hits = append(hits, ghapi.CodeHit{Repo: full, Path: r.File.Path})
			}
			u = p.Next
		}
	}
	if len(errs) == len(c.workspaces) {
		// Every workspace failed: that is an error, not an empty result.
		return hits, total, fmt.Errorf("code search %q: %s", query, strings.Join(errs, "; "))
	}
	for _, e := range errs {
		c.logf("code search: %s", e)
	}
	return hits, total, nil
}

func (c *Client) getSearch(ctx context.Context, u string, v any) error {
	c.searchMu.Lock()
	if wait := searchInterval - time.Since(c.lastSearch); wait > 0 {
		if !sleepCtx(ctx, wait) {
			c.searchMu.Unlock()
			return ctx.Err()
		}
	}
	c.lastSearch = time.Now()
	c.searchMu.Unlock()
	return c.getJSON(ctx, u, v)
}

// translateQuery maps the engine's GitHub-flavoured query to Bitbucket syntax.
func translateQuery(q string) string {
	var out []string
	for _, tok := range strings.Fields(q) {
		switch {
		case strings.HasPrefix(tok, "language:"):
			out = append(out, "ext:"+strings.TrimPrefix(tok, "language:"))
		case strings.HasPrefix(tok, "path:"):
			// Bitbucket has no path qualifier; the term itself still matches
			// path segments, so keep the value and drop the prefix.
			out = append(out, strings.TrimPrefix(tok, "path:"))
		case strings.HasPrefix(tok, "repo:"), strings.HasPrefix(tok, "ext:"):
			out = append(out, tok)
		case strings.Contains(tok, ":") && !strings.HasPrefix(tok, `"`):
			// Unknown GitHub qualifier: drop rather than send as a literal term.
			continue
		default:
			out = append(out, tok)
		}
	}
	return strings.Join(out, " ")
}

// ReposForIdentity is unavailable: Bitbucket Cloud has no commit search across
// repositories, so an author identity cannot be followed to other projects.
func (c *Client) ReposForIdentity(_ context.Context, name, email string) ([]string, error) {
	return nil, fmt.Errorf("follow identity %s <%s>: %w (no cross-repository commit search)", name, email, ErrUnsupported)
}

// Canary implements crawl.CanaryProvider. Bitbucket answers a malformed query
// with an HTTP error rather than an empty result set, which is the failure the
// GitHub canary exists to catch, so no probe query is needed here. The engine
// still reports the reason so the decision is visible in the event log.
func (c *Client) Canary() (query string, needed bool, why string) {
	return "", false, "Bitbucket code search reports malformed queries and unreachable workspaces as errors, never as zero results"
}

// RepoURL returns the web page of a repository.
func RepoURL(fullName string) string { return webBase + "/" + fullName }

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
