package graph

import (
	"strings"
	"testing"

	"skarvel/internal/criteria"
)

func TestProvenanceChainReachesSeed(t *testing.T) {
	g := New()
	g.AddSeed(KindAccount, "seeduser")

	_, _ = g.Discover(ID(KindAccount, "seeduser"), KindRepo, "victim/app", "authored-commits", criteria.TierB, false)
	_, _ = g.Discover(ID(KindRepo, "victim/app"), KindFile, "victim/app:src/x.js", "ioc-domain", criteria.TierA, false)

	chain := g.Chain(ID(KindFile, "victim/app:src/x.js"))
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(chain))
	}
	if chain[0].Kind != KindAccount || chain[0].Key != "seeduser" {
		t.Errorf("chain must start at the seed, got %v %q", chain[0].Kind, chain[0].Key)
	}
	s := g.ChainString(ID(KindFile, "victim/app:src/x.js"))
	if !strings.Contains(s, "ioc-domain") || !strings.Contains(s, "seeduser") {
		t.Errorf("chain string lost its reasons: %q", s)
	}
}

// A node reached only through an identity match stays labelled a lead, and the
// label must survive further traversal -- otherwise a chain of inferences
// quietly launders a lead into an accusation.
func TestLeadTaintPropagates(t *testing.T) {
	g := New()
	g.AddSeed(KindAccount, "seed")

	g.Discover(ID(KindAccount, "seed"), KindIdentity, "Real Dev <r@x.io>", "identity-name", criteria.TierD, true)
	g.Discover(ID(KindIdentity, "Real Dev <r@x.io>"), KindRepo, "realdev/lib", "identity-repos", criteria.TierD, false)
	n, _ := g.Get(ID(KindRepo, "realdev/lib"))

	if !n.Lead {
		t.Fatal("a repo reached through an identity match must remain a lead")
	}
}

// Reaching the same node by evidence that does not depend on identity clears
// the taint: there is now a defensible path to it.
func TestNonLeadRouteClearsTaint(t *testing.T) {
	g := New()
	g.AddSeed(KindAccount, "seed")
	g.Discover(ID(KindAccount, "seed"), KindIdentity, "Real Dev <r@x.io>", "identity-name", criteria.TierD, true)
	g.Discover(ID(KindIdentity, "Real Dev <r@x.io>"), KindRepo, "realdev/lib", "identity-repos", criteria.TierD, false)

	g.Discover(ID(KindAccount, "seed"), KindRepo, "realdev/lib", "ioc-domain", criteria.TierA, false)
	n, _ := g.Get(ID(KindRepo, "realdev/lib"))
	if n.Lead {
		t.Error("an independent evidential route should clear the lead label")
	}
}

// Content dedup answers "is this payload novel to the crawl" -- a question
// about where to spend budget. It must not answer "is this repository
// compromised": the second repo carrying an identical planted file is just as
// compromised as the first.
func TestForkDedupCountsNoveltyButNotVerdicts(t *testing.T) {
	g := New()
	g.AddSeed(KindRepo, "a/one")
	g.AddSeed(KindRepo, "b/two")

	mk := func(repo string) criteria.Finding {
		return criteria.Finding{
			Signal: "ioc-domain", Tier: criteria.TierA, Subject: criteria.SubjectFile,
			Repo: repo, Path: "src/payload.js", Evidence: "ipregionchecker.org",
		}
	}
	if got := g.RecordFindings(ID(KindRepo, "a/one"), []criteria.Finding{mk("a/one")}); got != 1 {
		t.Fatalf("first sighting novel = %d, want 1", got)
	}
	if got := g.RecordFindings(ID(KindRepo, "b/two"), []criteria.Finding{mk("b/two")}); got != 0 {
		t.Errorf("second sighting novel = %d, want 0 (same payload)", got)
	}

	// Both were actually examined; an unexamined repo deliberately does not
	// count toward the malicious total.
	g.MarkVisited(ID(KindRepo, "a/one"))
	g.MarkVisited(ID(KindRepo, "b/two"))

	second, _ := g.Get(ID(KindRepo, "b/two"))
	if len(second.Findings) != 1 {
		t.Fatalf("second repo findings = %d, want 1: dedup must not strip its evidence",
			len(second.Findings))
	}
	if second.Verdict != criteria.VerdictMalicious {
		t.Errorf("second repo verdict = %v, want MALICIOUS", second.Verdict)
	}
	if st := g.Stats(); st.Malicious != 2 {
		t.Errorf("malicious = %d, want 2 — both repos carry the payload", st.Malicious)
	}
}

// The same finding reported twice for one node is still one finding.
func TestWithinNodeDedup(t *testing.T) {
	g := New()
	g.AddSeed(KindRepo, "a/one")
	f := criteria.Finding{Signal: "ioc-domain", Tier: criteria.TierA, Path: "x.js", Evidence: "e"}
	g.RecordFindings(ID(KindRepo, "a/one"), []criteria.Finding{f})
	g.RecordFindings(ID(KindRepo, "a/one"), []criteria.Finding{f})
	n, _ := g.Get(ID(KindRepo, "a/one"))
	if len(n.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(n.Findings))
	}
}

// A dossier about the campaign is not a compromised repository.
func TestCorpusNotCountedAsMalicious(t *testing.T) {
	g := New()
	g.AddSeed(KindRepo, "researcher/dossiers")
	g.RecordFindings(ID(KindRepo, "researcher/dossiers"), []criteria.Finding{{
		Signal: "indicator-code-search", Tier: criteria.TierA, Path: "iocs.csv", Evidence: "evil.example",
	}})
	g.MarkVisited(ID(KindRepo, "researcher/dossiers"))
	g.MarkCorpus(ID(KindRepo, "researcher/dossiers"), "incident dossier")

	if st := g.Stats(); st.Malicious != 0 || st.Corpus != 1 {
		t.Errorf("malicious=%d corpus=%d, want 0/1", st.Malicious, st.Corpus)
	}
	n, _ := g.Get(ID(KindRepo, "researcher/dossiers"))
	if len(n.Findings) == 0 {
		t.Error("a corpus keeps its findings — they are worth reading")
	}
}

func TestShorterPathUpdatesHops(t *testing.T) {
	g := New()
	g.AddSeed(KindAccount, "seed")
	g.Discover(ID(KindAccount, "seed"), KindRepo, "x/a", "r", criteria.TierB, false)
	g.Discover(ID(KindRepo, "x/a"), KindRepo, "x/b", "r", criteria.TierB, false)
	g.Discover(ID(KindRepo, "x/b"), KindRepo, "x/c", "r", criteria.TierB, false)

	n, _ := g.Get(ID(KindRepo, "x/c"))
	if n.Hops != 3 {
		t.Fatalf("hops = %d, want 3", n.Hops)
	}
	g.Discover(ID(KindAccount, "seed"), KindRepo, "x/c", "direct", criteria.TierA, false)
	n, _ = g.Get(ID(KindRepo, "x/c"))
	if n.Hops != 1 {
		t.Errorf("hops after shorter route = %d, want 1", n.Hops)
	}
}

func TestVerdictRecomputedOnRecord(t *testing.T) {
	g := New()
	g.AddSeed(KindRepo, "x/a")
	id := ID(KindRepo, "x/a")

	g.RecordFindings(id, []criteria.Finding{{
		Signal: "remote-eval", Tier: criteria.TierB, Path: "a.js", Evidence: "eval(res.data)",
	}})
	n, _ := g.Get(id)
	if n.Verdict != criteria.VerdictReview {
		t.Fatalf("verdict = %v, want REVIEW after one strong signal", n.Verdict)
	}

	g.RecordFindings(id, []criteria.Finding{{
		Signal: "vscode-autorun-task", Tier: criteria.TierB, Path: "tasks.json", Evidence: "folderOpen",
	}})
	n, _ = g.Get(id)
	if n.Verdict != criteria.VerdictMalicious {
		t.Errorf("verdict = %v, want MALICIOUS after two strong signals", n.Verdict)
	}
}

// A repository found by search but never cloned must not be counted as
// malicious: the header would then disagree with the listing beneath it.
func TestUnexaminedRepoIsNotMalicious(t *testing.T) {
	g := New()
	g.AddSeed(KindRepo, "found/but-not-checked")
	g.RecordFindings(ID(KindRepo, "found/but-not-checked"), []criteria.Finding{{
		Signal: "indicator-code-search", Tier: criteria.TierA, Path: "src/x.js", Evidence: "evil",
	}})

	st := g.Stats()
	if st.Malicious != 0 {
		t.Errorf("malicious = %d, want 0 — it was never examined", st.Malicious)
	}
	if st.Unexamined != 1 {
		t.Errorf("unexamined = %d, want 1", st.Unexamined)
	}
}
