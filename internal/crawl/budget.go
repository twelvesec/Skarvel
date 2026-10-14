package crawl

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Budget bounds a crawl in the dimensions that actually run out.
//
// Depth is present only as a runaway ceiling. The binding constraints are API
// quota and time: at 5,000 REST requests per hour, 30 code searches per minute,
// plus clone time, a serious crawl is measured in hours. Disk matters because
// blobless clones are ~18% of a full clone, which is still substantial across
// several hundred repositories.
type Budget struct {
	MaxAPICalls  int64
	MaxSearches  int64
	MaxRepos     int64
	MaxDiskBytes int64
	MaxDepth     int
	MaxDuration  time.Duration

	apiCalls  atomic.Int64
	searches  atomic.Int64
	repos     atomic.Int64
	diskBytes atomic.Int64
	started   time.Time

	mu      sync.Mutex
	stopped bool
	stopWhy string
}

// DefaultBudget is deliberately conservative. An autonomous crawler that
// surprises its operator with a multi-day run has failed regardless of what it
// found.
func DefaultBudget() *Budget {
	return &Budget{
		MaxAPICalls:  20000,
		MaxSearches:  500,
		MaxRepos:     300,
		MaxDiskBytes: 20 << 30, // 20 GiB
		MaxDepth:     6,
		MaxDuration:  4 * time.Hour,
		started:      time.Now(),
	}
}

// Start marks the beginning of the run.
func (b *Budget) Start() { b.started = time.Now() }

// SpendAPI records API calls and reports whether budget remains.
func (b *Budget) SpendAPI(n int64) bool {
	v := b.apiCalls.Add(n)
	if b.MaxAPICalls > 0 && v > b.MaxAPICalls {
		b.stop("API call budget exhausted")
		return false
	}
	return true
}

func (b *Budget) SpendSearch(n int64) bool {
	v := b.searches.Add(n)
	if b.MaxSearches > 0 && v > b.MaxSearches {
		b.stop("search budget exhausted")
		return false
	}
	return true
}

func (b *Budget) SpendRepo() bool {
	v := b.repos.Add(1)
	if b.MaxRepos > 0 && v > b.MaxRepos {
		b.stop("repository budget exhausted")
		return false
	}
	return true
}

func (b *Budget) SpendDisk(n int64) bool {
	v := b.diskBytes.Add(n)
	if b.MaxDiskBytes > 0 && v > b.MaxDiskBytes {
		b.stop("disk budget exhausted")
		return false
	}
	return true
}

// ReleaseDisk returns space after a clone is evicted.
//
// Clones are analysed and dropped rather than retained: keeping several hundred
// of them is what turns a long crawl into a full disk, and everything worth
// keeping has already been extracted into findings by then.
func (b *Budget) ReleaseDisk(n int64) { b.diskBytes.Add(-n) }

// DepthOK reports whether a hop count is within the runaway ceiling.
func (b *Budget) DepthOK(hops int) bool { return b.MaxDepth <= 0 || hops <= b.MaxDepth }

// Expired reports whether the wall-clock budget has run out.
func (b *Budget) Expired() bool {
	if b.MaxDuration > 0 && time.Since(b.started) > b.MaxDuration {
		b.stop("time budget exhausted")
		return true
	}
	return b.Stopped()
}

func (b *Budget) stop(why string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.stopped {
		b.stopped, b.stopWhy = true, why
	}
}

// Halt stops the crawl for a reason outside the budget -- a failed search
// canary, for instance, where continuing would record false negatives.
func (b *Budget) Halt(why string) { b.stop(why) }

func (b *Budget) Stopped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopped
}

func (b *Budget) StopReason() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopWhy
}

// Usage is a snapshot for the TUI's burn-down pane.
type Usage struct {
	APICalls, MaxAPICalls int64
	Searches, MaxSearches int64
	Repos, MaxRepos       int64
	DiskBytes, MaxDisk    int64
	Elapsed, MaxDuration  time.Duration
}

func (b *Budget) Usage() Usage {
	return Usage{
		APICalls: b.apiCalls.Load(), MaxAPICalls: b.MaxAPICalls,
		Searches: b.searches.Load(), MaxSearches: b.MaxSearches,
		Repos: b.repos.Load(), MaxRepos: b.MaxRepos,
		DiskBytes: b.diskBytes.Load(), MaxDisk: b.MaxDiskBytes,
		Elapsed: time.Since(b.started), MaxDuration: b.MaxDuration,
	}
}

func (u Usage) String() string {
	return fmt.Sprintf("api %d/%d  search %d/%d  repos %d/%d  disk %.1f/%.0f GiB  %s/%s",
		u.APICalls, u.MaxAPICalls, u.Searches, u.MaxSearches, u.Repos, u.MaxRepos,
		float64(u.DiskBytes)/(1<<30), float64(u.MaxDisk)/(1<<30),
		u.Elapsed.Truncate(time.Second), u.MaxDuration)
}
