// Package ghapi is a minimal GitHub REST client covering the discovery phase.
//
// skarvel uses the API only to find candidate repositories and to learn which
// commit emails belong to the target login. All commit and file extraction
// happens offline against local clones, so this client issues on the order of
// tens of requests per hunt rather than one per commit.
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://api.github.com"
	userAgent      = "skarvel/0.1"
	apiVersion     = "2022-11-28"

	// GitHub allows 30 search requests per minute. Spacing them slightly wider
	// than 2s keeps us clear of the limit without needing to react to it.
	searchInterval = 2100 * time.Millisecond

	maxRetries = 5
)

// Client talks to the GitHub REST API.
type Client struct {
	http    *http.Client
	baseURL string
	token   string

	// searchMu serialises search requests so the interval throttle holds even
	// if callers get concurrent.
	searchMu   sync.Mutex
	lastSearch time.Time

	// Verbose logging sink; nil disables it.
	Logf func(format string, args ...any)
}

// New returns a Client authenticating with the given token.
//
// The token needs no scopes: reading public data works with an empty-scope PAT,
// which keeps the blast radius near zero if it leaks.
func New(token string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 45 * time.Second},
		baseURL: defaultBaseURL,
		token:   token,
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// ErrNotFound indicates a 404 from the API.
var ErrNotFound = errors.New("not found")

// do issues a request, retrying on rate limits and transient failures.
//
// Two distinct throttles apply. The primary limit reports itself through
// x-ratelimit-remaining plus a reset timestamp; the secondary ("abuse") limit
// appears as a 403 or 429 carrying retry-after and triggers on burstiness
// rather than volume. Both are handled by waiting, since neither is avoidable
// by retrying faster.
func (c *Client) do(ctx context.Context, url string) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", apiVersion)
		req.Header.Set("User-Agent", userAgent)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
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
			resp.Body.Close()
			return nil, errors.New("401 unauthorized: GITHUB_TOKEN is missing, expired, or malformed")

		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			wait, ok := rateLimitWait(resp, string(body), attempt)
			if !ok {
				return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
			}
			c.logf("rate limited, waiting %s", wait.Round(time.Second))
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

// rateLimitWait determines how long to wait after a 403/429, and whether the
// response actually represents a rate limit rather than a plain refusal.
//
// GitHub signals throttling three different ways and only the first two are
// visible in headers. The secondary ("abuse") limit frequently arrives as a
// bare 403 carrying neither retry-after nor an exhausted x-ratelimit-remaining,
// with the explanation only in the JSON body -- so the body has to be inspected
// or a long run dies on a limit that was always meant to be waited out.
func rateLimitWait(resp *http.Response, body string, attempt int) (time.Duration, bool) {
	if ra := resp.Header.Get("retry-after"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			return time.Duration(secs)*time.Second + time.Second, true
		}
	}
	if isSecondaryLimit(body) {
		// GitHub's documented guidance is to wait at least a minute, then back
		// off further if it recurs.
		d := time.Duration(60<<attempt) * time.Second
		if d > 5*time.Minute {
			d = 5 * time.Minute
		}
		return d, true
	}
	if resp.Header.Get("x-ratelimit-remaining") == "0" {
		if reset := resp.Header.Get("x-ratelimit-reset"); reset != "" {
			if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
				d := time.Until(time.Unix(epoch, 0)) + 2*time.Second
				if d < 0 {
					d = time.Second
				}
				// Cap the wait so a clock skew or a long core-limit reset does
				// not silently park the tool for an hour without warning.
				if d > 15*time.Minute {
					return 0, false
				}
				return d, true
			}
		}
	}
	return 0, false
}

// isSecondaryLimit recognises the secondary-rate-limit body, which is the only
// place GitHub reliably reports it.
func isSecondaryLimit(body string) bool {
	b := strings.ToLower(body)
	return strings.Contains(b, "secondary rate limit") ||
		strings.Contains(b, "abuse detection") ||
		strings.Contains(b, "please wait a few minutes")
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

// getJSON fetches a URL and decodes the body into v, returning the parsed Link
// header so callers can follow pagination.
func (c *Client) getJSON(ctx context.Context, url string, v any) (links, error) {
	resp, err := c.do(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	return parseLinks(resp.Header.Get("Link")), nil
}

// getSearch is getJSON with the search-endpoint throttle applied.
func (c *Client) getSearch(ctx context.Context, url string, v any) (links, error) {
	c.searchMu.Lock()
	if wait := searchInterval - time.Since(c.lastSearch); wait > 0 {
		if !sleepCtx(ctx, wait) {
			c.searchMu.Unlock()
			return nil, ctx.Err()
		}
	}
	c.lastSearch = time.Now()
	c.searchMu.Unlock()

	return c.getJSON(ctx, url, v)
}

// links holds the rel->url pairs from a Link header.
type links map[string]string

func parseLinks(header string) links {
	out := links{}
	for _, part := range strings.Split(header, ",") {
		segs := strings.Split(strings.TrimSpace(part), ";")
		if len(segs) < 2 {
			continue
		}
		url := strings.Trim(strings.TrimSpace(segs[0]), "<>")
		for _, s := range segs[1:] {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, `rel="`) {
				out[strings.Trim(strings.TrimPrefix(s, "rel="), `"`)] = url
			}
		}
	}
	return out
}

// paginate walks every page of a list endpoint, invoking fn on each page's
// decoded payload. fn returning false stops the walk early.
func (c *Client) paginate(ctx context.Context, url string, newPage func() any, fn func(any) bool) error {
	for url != "" {
		page := newPage()
		lk, err := c.getJSON(ctx, url, page)
		if err != nil {
			return err
		}
		if !fn(page) {
			return nil
		}
		url = lk["next"]
	}
	return nil
}

// RateLimit reports the current core and search quotas.
type RateLimit struct {
	Resources struct {
		Core   Quota `json:"core"`
		Search Quota `json:"search"`
	} `json:"resources"`
}

// Quota is one rate-limit bucket.
type Quota struct {
	Limit     int   `json:"limit"`
	Remaining int   `json:"remaining"`
	Reset     int64 `json:"reset"`
}

// RateLimit fetches current quota usage. This endpoint does not itself count
// against the limit, so it is safe to call for a preflight check.
func (c *Client) RateLimit(ctx context.Context) (*RateLimit, error) {
	var rl RateLimit
	if _, err := c.getJSON(ctx, c.baseURL+"/rate_limit", &rl); err != nil {
		return nil, err
	}
	return &rl, nil
}

// CheckAuth verifies the token before a hunt starts.
//
// Every search on a rejected token fails, and a crawl whose searches all fail
// finds nothing -- which, reported as a result, reads exactly like a clean
// sweep. /rate_limit costs no quota and answers 401 for a bad token.
func (c *Client) CheckAuth(ctx context.Context) error {
	var v struct {
		Resources struct {
			CodeSearch struct {
				Remaining int `json:"remaining"`
			} `json:"code_search"`
		} `json:"resources"`
	}
	_, err := c.getJSON(ctx, c.baseURL+"/rate_limit", &v)
	return err
}
