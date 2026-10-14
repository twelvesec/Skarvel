// Package event is the crawl's output channel.
//
// The TUI is a view over this bus and nothing more. Coupling the crawl to a
// terminal renderer would make it impossible to run under cron, impossible to
// test, and impossible to pipe findings into a case file -- so the engine only
// ever emits events, and both the TUI and the JSONL writer are subscribers.
package event

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

type Kind string

const (
	KindLog       Kind = "log"
	KindDiscover  Kind = "discover"  // a node entered the graph
	KindVisit     Kind = "visit"     // a node is being processed
	KindFinding   Kind = "finding"   // evidence recorded
	KindVerdict   Kind = "verdict"   // a node's verdict settled
	KindIndicator Kind = "indicator" // an indicator was promoted or queued
	KindReview    Kind = "review"    // something needing human sign-off
	KindBudget    Kind = "budget"    // periodic burn-down snapshot
	KindRound     Kind = "round"     // a crawl round closed
	KindHalt      Kind = "halt"      // the crawl stopped, with a reason
	KindDone      Kind = "done"
)

// Event is one thing that happened. Fields are deliberately flat so the JSONL
// form is greppable without a schema.
type Event struct {
	Time time.Time `json:"time"`
	Kind Kind      `json:"kind"`

	Node     string `json:"node,omitempty"`
	NodeKind string `json:"node_kind,omitempty"`
	Repo     string `json:"repo,omitempty"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	// URL is a permanent link to the exact line, so a hit can be opened
	// straight from the log without reconstructing it by hand.
	URL string `json:"url,omitempty"`

	Signal  string `json:"signal,omitempty"`
	Tier    string `json:"tier,omitempty"`
	Verdict string `json:"verdict,omitempty"`
	Score   int    `json:"score,omitempty"`
	Hops    int    `json:"hops,omitempty"`

	// Lead marks anything derived from a Tier-D identity match, so a consumer
	// can never mistake a lead for evidence.
	Lead bool `json:"lead,omitempty"`

	// Chain is the provenance path back to the seed, present on findings so a
	// reader can audit how the crawler arrived there.
	Chain string `json:"chain,omitempty"`

	Message  string `json:"message,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// Bus fans events out to subscribers.
//
// Slow subscribers drop events rather than blocking the crawl: a stalled
// renderer must never become backpressure on the hunt.
type Bus struct {
	mu     sync.RWMutex
	subs   []chan Event
	closed bool
}

func NewBus() *Bus { return &Bus{} }

func (b *Bus) Subscribe(buffer int) <-chan Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Event, buffer)
	b.subs = append(b.subs, ch)
	return ch
}

func (b *Bus) Emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // drop rather than stall the crawl
		}
	}
}

func (b *Bus) Logf(format string, args ...any) {
	b.Emit(Event{Kind: KindLog, Message: fmt.Sprintf(format, args...)})
}

func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for _, ch := range b.subs {
		close(ch)
	}
}

// WriteJSONL streams events to w until the channel closes. This is the
// headless path, and it is exactly as complete as the TUI path.
func WriteJSONL(w io.Writer, ch <-chan Event) error {
	enc := json.NewEncoder(w)
	for e := range ch {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
