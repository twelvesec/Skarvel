// Package crawl drives the expansion loop: what to look at next, how much
// budget remains, and when to stop.
package crawl

import (
	"container/heap"
	"math"
	"sync"

	"skarvel/internal/graph"
)

// HopDecay is the per-hop priority multiplier.
//
// A repository reached through a definitive C2 string should outrank one
// reached through a co-contributor three hops out, even when both carry the
// same local evidence. Without decay the frontier flattens into breadth-first
// order and the crawl drifts away from the campaign.
const HopDecay = 0.6

// ExpandThreshold is the score at or above which a node may grow the frontier.
// It matches criteria.TierB, so a single strong signal qualifies and no
// accumulation of supporting signals ever does.
const ExpandThreshold = 60

// Item is one unit of queued work.
type Item struct {
	NodeID string
	Kind   graph.Kind
	Score  int
	Hops   int

	// Lead marks work admitted only because the frontier ran dry. These are
	// pursued at reduced priority and stay labelled throughout.
	Lead bool

	priority float64
	index    int
}

// Priority is score decayed by distance from the seed.
//
// Leads are divided rather than excluded: when the evidential frontier is
// exhausted they are all that remains, and they should still be ordered
// sensibly among themselves.
func Priority(score, hops int, lead bool) float64 {
	p := float64(score) * math.Pow(HopDecay, float64(hops))
	if lead {
		p /= 100
	}
	return p
}

type pq []*Item

func (q pq) Len() int           { return len(q) }
func (q pq) Less(i, j int) bool { return q[i].priority > q[j].priority } // max-heap
func (q pq) Swap(i, j int)      { q[i], q[j] = q[j], q[i]; q[i].index = i; q[j].index = j }
func (q *pq) Push(x any)        { it := x.(*Item); it.index = len(*q); *q = append(*q, it) }
func (q *pq) Pop() any {
	old := *q
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*q = old[:n-1]
	return it
}

// Frontier is the scored work queue.
//
// It is a priority queue rather than a FIFO because depth is not a usable
// budget here: with a branching factor between 5 and 100, one more level is
// either nothing or a million nodes. Ordering by evidence and spending a fixed
// budget is controllable in a way that depth is not.
type Frontier struct {
	mu       sync.Mutex
	q        pq
	queued   map[string]bool
	done     map[string]bool
	deferred []*Item // leads held back until the evidential frontier is dry

	// dryRounds counts consecutive completed rounds that produced no node
	// scoring at or above the expansion threshold.
	dryRounds int
	admitted  int
}

func NewFrontier() *Frontier {
	f := &Frontier{queued: map[string]bool{}, done: map[string]bool{}}
	heap.Init(&f.q)
	return f
}

// Push admits work. Nodes already queued or completed are ignored, which is
// what stops fork cycles from spinning the crawl forever.
func (f *Frontier) Push(it *Item) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.queued[it.NodeID] || f.done[it.NodeID] {
		return false
	}
	it.priority = Priority(it.Score, it.Hops, it.Lead)

	// Leads are held out of the main queue entirely. They are not evidence and
	// must not compete with it, however many accumulate.
	if it.Lead {
		f.deferred = append(f.deferred, it)
		f.queued[it.NodeID] = true
		return true
	}

	f.queued[it.NodeID] = true
	heap.Push(&f.q, it)
	if it.Score >= ExpandThreshold {
		f.admitted++
	}
	return true
}

// Pop returns the highest-priority work, or nil when nothing remains.
func (f *Frontier) Pop() *Item {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.q.Len() == 0 {
		return nil
	}
	it := heap.Pop(&f.q).(*Item)
	delete(f.queued, it.NodeID)
	f.done[it.NodeID] = true
	return it
}

// Len reports the queued evidential work, excluding deferred leads.
func (f *Frontier) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.q.Len()
}

// PendingLeads reports how many leads are held back.
func (f *Frontier) PendingLeads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.deferred)
}

// EndRound closes a round and reports whether the crawl has gone dry.
//
// Dryness is measured in consecutive rounds that admitted nothing worth
// expanding, rather than by an empty queue: a queue can hold plenty of
// low-scoring work that will never justify going further.
func (f *Frontier) EndRound() (dry bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.admitted == 0 {
		f.dryRounds++
	} else {
		f.dryRounds = 0
	}
	f.admitted = 0
	return f.dryRounds >= 2
}

// ReleaseLeads moves deferred leads into the queue.
//
// This is the cold-start pass of tool.md section 9: only once the evidential
// frontier is exhausted, and only to find campaign branches that share no
// infrastructure with the seed. Everything it yields stays labelled a lead.
func (f *Frontier) ReleaseLeads() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := len(f.deferred)
	for _, it := range f.deferred {
		heap.Push(&f.q, it)
	}
	f.deferred = nil
	f.dryRounds = 0
	return n
}
