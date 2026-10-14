// Package graph holds what the crawl has discovered and, for every node, why.
//
// The "why" is not decoration. An autonomous crawler produces claims about
// repositories and people that will end up in a report, so each node carries an
// unbroken chain of edges back to the seed. That chain is what allows a finding
// to be defended -- specifically, it allows it to be shown that no conclusion
// rests on a Tier-D identity match (tool.md section 9).
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"skarvel/internal/criteria"
)

// Kind is the type of a node.
type Kind int

const (
	KindAccount Kind = iota
	KindRepo
	KindIdentity // a git author identity: name/email, not a platform account
	KindCommit
	KindFile
	KindIndicator
)

func (k Kind) String() string {
	switch k {
	case KindAccount:
		return "account"
	case KindRepo:
		return "repo"
	case KindIdentity:
		return "identity"
	case KindCommit:
		return "commit"
	case KindFile:
		return "file"
	case KindIndicator:
		return "indicator"
	}
	return "unknown"
}

// Node is one discovered entity.
type Node struct {
	Kind Kind
	Key  string // canonical: "owner/name" for repos, "name <email>" for identities

	// Hops is the distance from the seed, used for priority decay.
	Hops int

	// Score is the accumulated evidence score. Leads contribute nothing.
	Score int

	Verdict  criteria.Verdict
	Findings []criteria.Finding

	// Lead marks a node reached only through a Tier-D identity match. Anything
	// derived from a lead stays labelled as one, however far the crawl travels
	// from it, so a chain of inferences cannot quietly become an accusation.
	Lead bool

	// Corpus marks a repository that deliberately collects malicious material --
	// a research dossier, advisory database or sample archive. Its findings are
	// real matches but say nothing about the repository, so it is reported
	// separately and never counted as compromised.
	Corpus       bool
	CorpusReason string

	// Warned marks a repository whose own description or README says it holds
	// malicious code and must not be run (a researcher's or victim's copy of a
	// lure). It is analysed and its findings kept, but it is reported in its own
	// section and never counted as a confirmed operator repository. The notice is
	// the owner's unverified claim, so it moves the repository, never hides it.
	Warned     bool
	WarnReason string

	// Visited records that the node has been fully processed, as opposed to
	// merely discovered and queued.
	Visited    bool
	Discovered time.Time

	// Examined records that the repository was actually cloned and analysed.
	// Visited is set when processing starts, so a repository refused for size
	// or budget is Visited but not Examined -- and a verdict resting only on a
	// search-index hit must never be reported as a confirmed examination.
	Examined bool

	// seen deduplicates findings within this node only.
	seen map[string]bool

	// From is the node this was reached from, empty for seeds.
	From string
	// Reason is why the edge was taken -- the signal name that licensed it.
	Reason string
}

// Edge is a traversal that happened, retained for the provenance chain.
type Edge struct {
	From, To string
	Reason   string
	Tier     criteria.Tier
}

// Graph is the accumulated state of a crawl. Safe for concurrent use: the
// crawler runs workers in parallel against a shared frontier.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges []Edge

	// findingSeen deduplicates by content, not by location. One malicious file
	// copied across fifty forks is one finding, and without this the crawl
	// spends its entire budget re-confirming the same payload.
	findingSeen map[string]bool
}

func New() *Graph {
	return &Graph{
		nodes:       map[string]*Node{},
		findingSeen: map[string]bool{},
	}
}

// ID builds the canonical node identifier.
func ID(k Kind, key string) string { return k.String() + ":" + key }

// AddSeed inserts a root node with no provenance.
func (g *Graph) AddSeed(k Kind, key string) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := ID(k, key)
	if n, ok := g.nodes[id]; ok {
		return n
	}
	n := &Node{Kind: k, Key: key, Hops: 0, Discovered: time.Now(), Reason: "seed"}
	g.nodes[id] = n
	return n
}

// Discover records reaching `to` from `from`. It returns the node and whether
// it was newly created.
//
// Re-discovery via a shorter path updates the hop count, because priority decays
// with distance and a node found late by a short route should not be penalised
// for having been found earlier by a long one.
func (g *Graph) Discover(from string, k Kind, key, reason string, tier criteria.Tier, lead bool) (*Node, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := ID(k, key)
	parentHops := 0
	if p, ok := g.nodes[from]; ok {
		parentHops = p.Hops
		// A lead taints everything downstream of it.
		lead = lead || p.Lead
	}

	g.edges = append(g.edges, Edge{From: from, To: id, Reason: reason, Tier: tier})

	if n, ok := g.nodes[id]; ok {
		if parentHops+1 < n.Hops {
			n.Hops = parentHops + 1
			n.From, n.Reason = from, reason
		}
		// Reaching a node by a non-lead route clears the taint: there is now a
		// path to it that does not depend on an identity match.
		if !lead {
			n.Lead = false
		}
		return n, false
	}

	n := &Node{
		Kind: k, Key: key,
		Hops:       parentHops + 1,
		Discovered: time.Now(),
		From:       from,
		Reason:     reason,
		Lead:       lead,
	}
	g.nodes[id] = n
	return n, true
}

// Get returns a node by id.
func (g *Graph) Get(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// RecordFindings attaches evidence to a node and recomputes its verdict.
//
// Findings already seen by content are dropped, and the count of newly retained
// ones is returned so the caller can tell a genuine discovery from the fiftieth
// fork of a known payload.
func (g *Graph) RecordFindings(id string, fs []criteria.Finding) (fresh int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	n, ok := g.nodes[id]
	if !ok {
		return 0
	}
	if n.seen == nil {
		n.seen = map[string]bool{}
	}
	for _, f := range fs {
		h := FindingHash(f)

		// Every node keeps its own evidence. Content dedup answers "is this
		// payload novel to the crawl", which is a question about where to
		// spend budget -- not about whether THIS repository is compromised.
		// Conflating the two silently left the second repository carrying an
		// identical planted file assessed as clean.
		if n.seen[h] {
			continue
		}
		n.seen[h] = true
		n.Findings = append(n.Findings, f)

		if !g.findingSeen[h] {
			g.findingSeen[h] = true
			fresh++
		}
	}
	a := criteria.Assess(n.Findings)
	n.Score, n.Verdict = a.Score, a.Verdict
	return fresh
}

// MarkCorpus records that a repository is a deliberate collection of malicious
// material rather than a victim or an operator asset.
func (g *Graph) MarkCorpus(id, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n, ok := g.nodes[id]; ok {
		n.Corpus, n.CorpusReason = true, reason
	}
}

// MarkWarned records that a repository carries its owner's warning notice.
func (g *Graph) MarkWarned(id, quote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n, ok := g.nodes[id]; ok {
		n.Warned, n.WarnReason = true, quote
	}
}

// FindingHash identifies a finding by what it *is*, deliberately excluding the
// repository it was found in.
//
// This is what makes fork deduplication work: the same payload at the same path
// with the same matched bytes is one finding, whether it appears in one
// repository or fifty. Including the repo would defeat the purpose.
func FindingHash(f criteria.Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.Signal, f.Path, f.Evidence, fmt.Sprint(f.Tier),
	}, "\x1f")))
	return hex.EncodeToString(h[:16])
}

// Chain reconstructs the provenance path from the seed to a node.
func (g *Graph) Chain(id string) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var out []Node
	seen := map[string]bool{}
	for cur := id; cur != ""; {
		if seen[cur] {
			break // defensive: a cycle must not hang the reporter
		}
		seen[cur] = true
		n, ok := g.nodes[cur]
		if !ok {
			break
		}
		out = append(out, *n)
		cur = n.From
	}
	// seed first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// ChainString renders a provenance chain for display and reports.
func (g *Graph) ChainString(id string) string {
	chain := g.Chain(id)
	var b strings.Builder
	for i, n := range chain {
		if i > 0 {
			b.WriteString(" --[" + n.Reason + "]--> ")
		}
		b.WriteString(n.Kind.String() + " " + n.Key)
	}
	return b.String()
}

// Stats summarises the graph for the TUI.
type Stats struct {
	Nodes, Visited, Edges int
	Malicious, Review     int
	Corpus                int
	Unexamined            int
	Leads                 int
	ByKind                map[Kind]int
	DistinctFindingHashes int
}

func (g *Graph) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	s := Stats{ByKind: map[Kind]int{}, Edges: len(g.edges), DistinctFindingHashes: len(g.findingSeen)}
	for _, n := range g.nodes {
		s.Nodes++
		s.ByKind[n.Kind]++
		if n.Visited {
			s.Visited++
		}
		if n.Lead {
			s.Leads++
		}
		if n.Corpus {
			s.Corpus++
			continue // a dossier about malware is not compromised
		}
		if n.Warned {
			continue // self-declared research copy: reported apart, not counted
		}
		if !n.Visited {
			// Counting an unexamined repository as malicious would make the
			// header disagree with the listing beneath it, which is how a
			// summary stops being trustworthy.
			if len(n.Findings) > 0 {
				s.Unexamined++
			}
			continue
		}
		switch n.Verdict {
		case criteria.VerdictMalicious:
			s.Malicious++
		case criteria.VerdictReview:
			s.Review++
		}
	}
	return s
}

// Nodes returns a snapshot ordered by score, strongest first.
func (g *Graph) Nodes() []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, *n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// MarkVisited flags a node as fully processed.
func (g *Graph) MarkVisited(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n, ok := g.nodes[id]; ok {
		n.Visited = true
	}
}

// MarkExamined flags a node as fully analysed.
func (g *Graph) MarkExamined(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n, ok := g.nodes[id]; ok {
		n.Examined = true
	}
}
