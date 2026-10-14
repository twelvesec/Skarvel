package ghapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// CodeHit is one code-search result.
type CodeHit struct {
	Repo string
	Path string
}

type codeSearchResp struct {
	TotalCount        int  `json:"total_count"`
	IncompleteResults bool `json:"incomplete_results"`
	Items             []struct {
		Path       string `json:"path"`
		Repository struct {
			FullName string `json:"full_name"`
			Fork     bool   `json:"fork"`
		} `json:"repository"`
	} `json:"items"`
}

// SearchCode runs a code search and returns the matching repositories.
//
// The returned total is the backend's own count, which the caller needs for the
// canary check: this endpoint answers a malformed or unsupported qualifier with
// zero results rather than an error, so a zero here is not evidence of absence
// until a query known to match has been confirmed to still match.
func (c *Client) SearchCode(ctx context.Context, query string, maxPages int) (hits []CodeHit, total int, err error) {
	if maxPages <= 0 {
		maxPages = 1
	}
	u := "https://api.github.com/search/code?per_page=100&q=" + url.QueryEscape(query)

	for page := 0; page < maxPages && u != ""; page++ {
		var resp codeSearchResp
		lk, err := c.getSearch(ctx, u, &resp)
		if err != nil {
			return hits, total, fmt.Errorf("code search %q: %w", query, err)
		}
		if page == 0 {
			total = resp.TotalCount
		}
		for _, it := range resp.Items {
			if it.Repository.FullName == "" {
				continue
			}
			hits = append(hits, CodeHit{Repo: it.Repository.FullName, Path: it.Path})
		}
		u = lk["next"]
	}
	return hits, total, nil
}

// RepoMeta is the repository detail the guards need.
type RepoMeta struct {
	FullName    string   `json:"full_name"`
	Description string   `json:"description"`
	Topics      []string `json:"topics"`
	Fork        bool     `json:"fork"`
	// Size is the repository size in kilobytes, as GitHub reports it. Used to
	// refuse clones that would stall the crawl.
	Size      int    `json:"size"`
	Private   bool   `json:"private"`
	CloneURL  string `json:"clone_url"`
	CreatedAt string `json:"created_at"`
	PushedAt  string `json:"pushed_at"`
	Owner     struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	Parent *struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
}

// GetRepo fetches repository metadata.
func (c *Client) GetRepo(ctx context.Context, fullName string) (*RepoMeta, error) {
	var m RepoMeta
	if _, err := c.getJSON(ctx, "https://api.github.com/repos/"+fullName, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// GetReadme returns the head of a repository's README, used by the
// corpus classifier. A missing README is not an error.
func (c *Client) GetReadme(ctx context.Context, fullName string, maxBytes int) (string, error) {
	var r struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if _, err := c.getJSON(ctx, "https://api.github.com/repos/"+fullName+"/readme", &r); err != nil {
		return "", nil
	}
	if r.Encoding != "base64" {
		return "", nil
	}
	dec, err := decodeBase64Lines(r.Content)
	if err != nil {
		return "", nil
	}
	if len(dec) > maxBytes {
		dec = dec[:maxBytes]
	}
	return string(dec), nil
}

func decodeBase64Lines(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "\n", "")
	return base64.StdEncoding.DecodeString(s)
}

type commitSearchResp struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	} `json:"items"`
}

// ReposForIdentity finds repositories containing commits by a git identity.
//
// Identity here is the unauthenticated name/email pair carried in commit
// metadata, not a platform account -- the two are routinely different, and in a
// campaign that forges commits they are different on purpose. Results are
// therefore places this identity STRING appears, which is exactly what is
// wanted when tracking an operator who reuses a persona.
func (c *Client) ReposForIdentity(ctx context.Context, name, email string) ([]string, error) {
	var q string
	switch {
	case email != "":
		q = "author-email:" + email
	case name != "":
		q = "author-name:" + strconv.Quote(name)
	default:
		return nil, nil
	}

	u := "https://api.github.com/search/commits?per_page=100&q=" + url.QueryEscape(q)
	var resp commitSearchResp
	if _, err := c.getSearch(ctx, u, &resp); err != nil {
		return nil, fmt.Errorf("commit search %q: %w", q, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, it := range resp.Items {
		full := it.Repository.FullName
		if full == "" || seen[full] {
			continue
		}
		seen[full] = true
		out = append(out, full)
	}
	return out, nil
}
