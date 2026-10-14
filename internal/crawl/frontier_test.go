package crawl

import (
	"testing"
	"time"

	"skarvel/internal/graph"
)

func TestPriorityDecaysWithDistance(t *testing.T) {
	near := Priority(60, 1, false)
	far := Priority(60, 4, false)
	if far >= near {
		t.Errorf("distant node priority %v should be below near %v", far, near)
	}
	// Strong evidence far out should still lose to definitive evidence close in.
	if Priority(100, 1, false) <= Priority(60, 1, false) {
		t.Error("definitive evidence should outrank strong at equal distance")
	}
}

func TestFrontierOrdersByEvidence(t *testing.T) {
	f := NewFrontier()
	f.Push(&Item{NodeID: "repo:weak", Score: 15, Hops: 1})
	f.Push(&Item{NodeID: "repo:strong", Score: 100, Hops: 1})
	f.Push(&Item{NodeID: "repo:mid", Score: 60, Hops: 1})

	want := []string{"repo:strong", "repo:mid", "repo:weak"}
	for _, w := range want {
		got := f.Pop()
		if got == nil || got.NodeID != w {
			t.Fatalf("pop = %v, want %s", got, w)
		}
	}
	if f.Pop() != nil {
		t.Error("frontier should be empty")
	}
}

func TestFrontierDedupesAndDoesNotRevisit(t *testing.T) {
	f := NewFrontier()
	if !f.Push(&Item{NodeID: "repo:a", Score: 100}) {
		t.Fatal("first push should be admitted")
	}
	if f.Push(&Item{NodeID: "repo:a", Score: 100}) {
		t.Error("duplicate queued item should be rejected")
	}
	f.Pop()
	if f.Push(&Item{NodeID: "repo:a", Score: 100}) {
		t.Error("completed item must not be requeued: fork cycles would spin forever")
	}
}

// Leads must not compete with evidence, however many accumulate.
func TestLeadsAreHeldBackUntilDry(t *testing.T) {
	f := NewFrontier()
	for i := 0; i < 100; i++ {
		f.Push(&Item{NodeID: "identity:lead" + string(rune('a'+i%26)) + string(rune('0'+i/26)), Score: 0, Lead: true})
	}
	f.Push(&Item{NodeID: "repo:real", Score: 60, Hops: 2})

	if f.Len() != 1 {
		t.Fatalf("evidential queue length = %d, want 1: leads must be deferred", f.Len())
	}
	if got := f.Pop(); got.NodeID != "repo:real" {
		t.Fatalf("pop = %s, want repo:real", got.NodeID)
	}
	if f.PendingLeads() == 0 {
		t.Fatal("leads should still be pending")
	}
	if n := f.ReleaseLeads(); n == 0 {
		t.Fatal("release should surface the deferred leads")
	}
	if f.Len() == 0 {
		t.Error("released leads should now be queued")
	}
	if it := f.Pop(); it == nil || !it.Lead {
		t.Error("work released from the lead pool must stay labelled a lead")
	}
}

func TestDryDetection(t *testing.T) {
	f := NewFrontier()
	f.Push(&Item{NodeID: "repo:a", Score: 100})
	if dry := f.EndRound(); dry {
		t.Error("a round that admitted strong evidence is not dry")
	}
	if dry := f.EndRound(); dry {
		t.Error("one empty round is not yet dry")
	}
	if dry := f.EndRound(); !dry {
		t.Error("two consecutive empty rounds should report dry")
	}
}

// Supporting evidence alone must never make a round productive.
func TestSupportingEvidenceDoesNotResetDryness(t *testing.T) {
	f := NewFrontier()
	f.Push(&Item{NodeID: "repo:c1", Score: 15})
	f.EndRound()
	f.Push(&Item{NodeID: "repo:c2", Score: 15})
	if dry := f.EndRound(); !dry {
		t.Error("rounds admitting only supporting evidence should count as dry")
	}
}

func TestBudgetStops(t *testing.T) {
	b := &Budget{MaxAPICalls: 10, MaxRepos: 2, MaxDepth: 3, MaxDuration: time.Hour}
	b.Start()

	if !b.SpendAPI(9) {
		t.Fatal("under budget should be allowed")
	}
	if b.SpendAPI(5) {
		t.Error("over budget should be refused")
	}
	if !b.Stopped() {
		t.Error("exceeding a budget should stop the crawl")
	}
	if b.StopReason() == "" {
		t.Error("a stop must carry a reason for the operator")
	}

	if !b.DepthOK(3) || b.DepthOK(4) {
		t.Error("depth ceiling misapplied")
	}
}

func TestDiskReleaseAllowsLongCrawls(t *testing.T) {
	b := &Budget{MaxDiskBytes: 100}
	b.Start()
	for i := 0; i < 50; i++ {
		if !b.SpendDisk(90) {
			t.Fatalf("clone %d refused; eviction should keep the crawl within budget", i)
		}
		b.ReleaseDisk(90)
	}
}

func TestHaltCarriesReason(t *testing.T) {
	b := DefaultBudget()
	b.Start()
	b.Halt("search canary returned zero: backend changed")
	if !b.Expired() {
		t.Error("a halt should end the crawl")
	}
	if b.StopReason() == "" {
		t.Error("halt reason lost")
	}
}

func TestItemKindPreserved(t *testing.T) {
	f := NewFrontier()
	f.Push(&Item{NodeID: "x", Kind: graph.KindIndicator, Score: 100})
	if got := f.Pop(); got.Kind != graph.KindIndicator {
		t.Errorf("kind = %v, want indicator", got.Kind)
	}
}
