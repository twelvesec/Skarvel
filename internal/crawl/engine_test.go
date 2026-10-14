package crawl

import (
	"context"
	"strings"
	"testing"

	"skarvel/internal/criteria"
	"skarvel/internal/event"
	"skarvel/internal/ghapi"
	"skarvel/internal/graph"
	"skarvel/internal/indicator"
	"skarvel/internal/model"
)

type fakeGH struct {
	repos      map[string][]string        // owner -> repo full names
	meta       map[string]*ghapi.RepoMeta //
	readme     map[string]string          //
	search     map[string][]ghapi.CodeHit // query -> hits
	identity   map[string][]string        // "name|email" -> repos
	canaryZero bool
	searches   []string
}

func (f *fakeGH) ListRepos(_ context.Context, owner string) ([]model.Repo, error) {
	var out []model.Repo
	for _, r := range f.repos[owner] {
		out = append(out, model.Repo{FullName: r})
	}
	return out, nil
}

func (f *fakeGH) GetRepo(_ context.Context, full string) (*ghapi.RepoMeta, error) {
	if m, ok := f.meta[full]; ok {
		return m, nil
	}
	m := &ghapi.RepoMeta{FullName: full}
	m.Owner.Login = strings.Split(full, "/")[0]
	return m, nil
}

func (f *fakeGH) GetReadme(_ context.Context, full string, _ int) (string, error) {
	return f.readme[full], nil
}

func (f *fakeGH) SearchCode(_ context.Context, q string, _ int) ([]ghapi.CodeHit, int, error) {
	f.searches = append(f.searches, q)
	if strings.Contains(q, "folderOpen") { // the canary
		if f.canaryZero {
			return nil, 0, nil
		}
		return nil, 384000, nil
	}
	hits := f.search[q]
	return hits, len(hits), nil
}

func (f *fakeGH) ReposForIdentity(_ context.Context, name, email string) ([]string, error) {
	return f.identity[name+"|"+email], nil
}

type fakeAnalyzer struct {
	byRepo map[string]Analysis
}

func (a *fakeAnalyzer) Analyze(_ context.Context, repo string, _ *ghapi.RepoMeta, _ *indicator.Set) (Analysis, error) {
	return a.byRepo[repo], nil
}

// collect subscribes and returns a function that closes the bus and drains
// every event synchronously. An earlier version consumed events in a goroutine
// and asserted on the slice while that goroutine was still appending to it --
// a data race that also made the assertions read an empty slice.
func collect(bus *event.Bus) func() []event.Event {
	ch := bus.Subscribe(8192)
	return func() []event.Event {
		bus.Close()
		var out []event.Event
		for e := range ch {
			out = append(out, e)
		}
		return out
	}
}

// The core loop: a seed indicator finds a repo with no social link to it, that
// repo's flagged author is expanded, and the author's other repo is reached.
func TestIndicatorFlywheelReachesUnconnectedRepos(t *testing.T) {
	gh := &fakeGH{
		search: map[string][]ghapi.CodeHit{
			`"evil.example.org"`: {{Repo: "victim/app", Path: "src/x.js"}},
		},
		identity: map[string][]string{
			"Op Persona|op@mail.invalid": {"operator/other"},
		},
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"victim/app": {
			Findings: []criteria.Finding{{
				Signal: "indicator-domain", Tier: criteria.TierA, Subject: criteria.SubjectFile,
				Repo: "victim/app", Path: "src/x.js", Evidence: "evil.example.org",
			}},
			Authors: []Identity{{Name: "Op Persona", Email: "op@mail.invalid"}},
		},
		"operator/other": {
			Findings: []criteria.Finding{{
				Signal: "remote-eval", Tier: criteria.TierB, Subject: criteria.SubjectFile,
				Repo: "operator/other", Path: "a.js", Evidence: "eval(res.data)",
			}},
		},
	}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"},
		Budget:     DefaultBudget(),
	})
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, ok := e.Graph().Get(graph.ID(graph.KindRepo, "victim/app")); !ok {
		t.Fatal("indicator search should have discovered victim/app")
	}
	if _, ok := e.Graph().Get(graph.ID(graph.KindRepo, "operator/other")); !ok {
		t.Fatal("the flagged author's other repository should have been reached")
	}

	chain := e.Graph().ChainString(graph.ID(graph.KindRepo, "operator/other"))
	if !strings.Contains(chain, "evil.example.org") {
		t.Errorf("provenance must trace back to the seed indicator, got %q", chain)
	}
}

// Containment must not imply authorship: finding a payload in a repository
// must not put its owner under investigation.
func TestVictimOwnerIsNotExpanded(t *testing.T) {
	gh := &fakeGH{
		search: map[string][]ghapi.CodeHit{
			`"evil.example.org"`: {{Repo: "innocent/company-app", Path: "src/x.js"}},
		},
		repos: map[string][]string{
			"innocent": {"innocent/other-project", "innocent/website"},
		},
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"innocent/company-app": {
			Findings: []criteria.Finding{{
				Signal: "indicator-domain", Tier: criteria.TierA, Subject: criteria.SubjectFile,
				Repo: "innocent/company-app", Path: "src/x.js", Evidence: "evil.example.org",
			}},
			Authors: []Identity{{Name: "Op", Email: "op@mail.invalid"}},
		},
	}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"},
		Budget:     DefaultBudget(),
	})
	e.Run(context.Background())

	for _, unwanted := range []string{"innocent/other-project", "innocent/website"} {
		if _, ok := e.Graph().Get(graph.ID(graph.KindRepo, unwanted)); ok {
			t.Errorf("%s was reached: a payload pushed INTO a repo does not "+
				"make its owner a suspect", unwanted)
		}
	}
	if _, ok := e.Graph().Get(graph.ID(graph.KindAccount, "innocent")); ok {
		t.Error("the victim account itself must not enter the graph")
	}
}

// A malware corpus is wall-to-wall Tier A. It must be recorded and abandoned,
// not expanded.
func TestCorpusRepoIsNotExpanded(t *testing.T) {
	gh := &fakeGH{
		search: map[string][]ghapi.CodeHit{
			`"evil.example.org"`: {{Repo: "ytisf/theZoo", Path: "samples/x.js"}},
		},
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"ytisf/theZoo": {
			Findings: []criteria.Finding{{
				Signal: "indicator-domain", Tier: criteria.TierA, Repo: "ytisf/theZoo",
			}},
			Authors: []Identity{{Name: "Researcher", Email: "r@x.io"}},
		},
	}}

	bus := event.NewBus()
	done := collect(bus)
	e := NewEngine(gh, an, bus, Options{Indicators: []string{"evil.example.org"}, Budget: DefaultBudget()})
	e.Run(context.Background())

	if _, ok := e.Graph().Get(graph.ID(graph.KindIdentity, "Researcher <r@x.io>")); ok {
		t.Error("a corpus repository's contributors must not be expanded")
	}
	found := false
	for _, ev := range done() {
		if strings.Contains(ev.Message, "not expanded") {
			found = true
		}
	}
	if !found {
		t.Error("the operator should be told the corpus was skipped and why")
	}
}

// A zero-result search only means "absent" if the canary proves the backend
// still works.
func TestCanaryFailureHaltsTheCrawl(t *testing.T) {
	gh := &fakeGH{canaryZero: true}
	bus := event.NewBus()
	done := collect(bus)

	e := NewEngine(gh, &fakeAnalyzer{}, bus, Options{
		Indicators: []string{"evil.example.org"}, Budget: DefaultBudget(),
	})
	err := e.Run(context.Background())
	if err == nil {
		t.Fatal("a failed canary must stop the crawl rather than record false negatives")
	}
	halted := false
	for _, ev := range done() {
		if ev.Kind == event.KindHalt {
			halted = true
		}
	}
	if !halted {
		t.Error("a halt event should be emitted")
	}
}

// Generic strings must never become search seeds automatically.
func TestGenericIndicatorIsQueuedNotPromoted(t *testing.T) {
	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"evil.example.org"`: {{Repo: "op/repo", Path: "x.js"}},
	}}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"op/repo": {
			Findings: []criteria.Finding{{Signal: "indicator-domain", Tier: criteria.TierA, Repo: "op/repo"}},
			Candidates: []indicator.Indicator{
				{Value: "processUserData", Kind: indicator.KindGeneric},
				{Value: "c2.evil-host.example", Kind: indicator.KindDomain},
			},
		},
	}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"}, AutoPromote: true, Budget: DefaultBudget(),
	})
	e.Run(context.Background())

	var queuedGeneric bool
	for _, q := range e.QueuedIndicators() {
		if q.Value == "processUserData" {
			queuedGeneric = true
		}
	}
	if !queuedGeneric {
		t.Error("a generic string must be queued for review, never auto-promoted")
	}
	for _, s := range gh.searches {
		if strings.Contains(s, "processUserData") {
			t.Fatal("a generic string was used as a search seed; this is how a hunt becomes a crawl of all of GitHub")
		}
	}
}

// The report lists what the hunt mined. Something already being hunted -- here
// the seed, found again inside a payload -- is not a discovery, and a string
// queued from several files is listed once.
func TestNewIndicatorsListsOnlyWhatIsNew(t *testing.T) {
	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"evil.example.org"`: {{Repo: "op/repo", Path: "x.js"}},
	}}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"op/repo": {
			Findings: []criteria.Finding{{Signal: "indicator-domain", Tier: criteria.TierA, Repo: "op/repo"}},
			Candidates: []indicator.Indicator{
				{Value: "evil.example.org", Kind: indicator.KindDomain, Source: "op/repo:x.js"}, // the seed again
				{Value: "c2.evil-host.io", Kind: indicator.KindDomain, Source: "op/repo:x.js"},
				{Value: "processUserData", Kind: indicator.KindGeneric, Source: "op/repo:x.js"},
				{Value: "processUserData", Kind: indicator.KindGeneric, Source: "op/repo:y.js"}, // duplicate
			},
		},
	}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"}, AutoPromote: true, Budget: DefaultBudget(),
		NoBuiltinIndicators: true,
	})
	e.Run(context.Background())

	promoted, candidates := e.NewIndicators()
	if len(promoted) != 1 || promoted[0].Value != "c2.evil-host.io" {
		t.Fatalf("promoted = %+v, want only c2.evil-host.io (the seed is not new)", promoted)
	}
	if promoted[0].Source != "op/repo:x.js" {
		t.Errorf("a promoted indicator must say where it was mined, got %q", promoted[0].Source)
	}
	if len(candidates) != 1 || candidates[0].Value != "processUserData" {
		t.Errorf("candidates = %+v, want processUserData once", candidates)
	}
}

func TestBudgetStopsTheCrawl(t *testing.T) {
	gh := &fakeGH{repos: map[string][]string{"seed": {}}}
	for i := 0; i < 100; i++ {
		gh.repos["seed"] = append(gh.repos["seed"], "seed/r"+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{}}

	bus := event.NewBus()
	defer bus.Close()
	b := DefaultBudget()
	b.MaxRepos = 5
	e := NewEngine(gh, an, bus, Options{Seed: "seed", Budget: b})
	e.Run(context.Background())

	if !b.Stopped() {
		t.Error("exceeding the repository budget should stop the crawl")
	}
}

// One fabricated history naming someone proves nothing -- somebody has to be
// the author of record. The second one is the operator reusing a name.
func TestIdentityLeadNeedsTwoFabricatedRepos(t *testing.T) {
	forged := criteria.TimestampResult{
		Considered: 200, OnHour: 150, Log10P: -400, Tier: criteria.TierB,
		DominantHour: 12, DominantCount: 150,
	}
	victim := Identity{Name: "Real Dev", Email: "real@dev.example"}

	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"evil.example.org"`: {
			{Repo: "op/one", Path: "a.js"},
			{Repo: "op/two", Path: "b.js"},
		},
	}}
	mk := func(repo string) Analysis {
		return Analysis{
			Findings:   []criteria.Finding{{Signal: "indicator-domain", Tier: criteria.TierA, Repo: repo, Path: "a.js"}},
			Timestamps: forged,
			Authors:    []Identity{victim},
		}
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{"op/one": mk("op/one"), "op/two": mk("op/two")}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{Indicators: []string{"evil.example.org"}, Budget: DefaultBudget()})
	e.Run(context.Background())

	var leads int
	for _, r := range e.Review() {
		if r.Signal == "identity-in-fabricated-history" {
			leads++
			if r.Tier != criteria.TierD {
				t.Errorf("tier = %v, want D", r.Tier)
			}
			if !strings.Contains(r.Why, "victim") {
				t.Error("a lead about a person must state they are more likely a victim")
			}
		}
	}
	if leads == 0 {
		t.Fatal("an identity in two fabricated histories should raise a lead")
	}

	// The lead must not have influenced any repository verdict.
	for _, n := range e.Graph().Nodes() {
		for _, f := range n.Findings {
			if f.Tier == criteria.TierD {
				t.Error("a Tier-D lead must never be recorded as node evidence")
			}
		}
	}
}

// Without --follow-leads, an identity lead must never be visited.
func TestLeadsNotFollowedByDefault(t *testing.T) {
	forged := criteria.TimestampResult{Considered: 200, OnHour: 150, Log10P: -400, Tier: criteria.TierB}
	victim := Identity{Name: "Real Dev", Email: "real@dev.example"}

	gh := &fakeGH{
		search: map[string][]ghapi.CodeHit{
			`"evil.example.org"`: {{Repo: "op/one", Path: "a.js"}, {Repo: "op/two", Path: "b.js"}},
		},
		identity: map[string][]string{
			"Real Dev|real@dev.example": {"realdev/legit-project"},
		},
	}
	mk := func(repo string) Analysis {
		return Analysis{
			Findings:   []criteria.Finding{{Signal: "indicator-domain", Tier: criteria.TierA, Repo: repo}},
			Timestamps: forged,
			Authors:    []Identity{victim},
		}
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{"op/one": mk("op/one"), "op/two": mk("op/two")}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{Indicators: []string{"evil.example.org"}, Budget: DefaultBudget()})
	e.Run(context.Background())

	if _, ok := e.Graph().Get(graph.ID(graph.KindRepo, "realdev/legit-project")); ok {
		t.Error("an innocent developer's project was crawled without --follow-leads")
	}
}

// A search hit must be visible immediately: repository and path are known as
// soon as the search returns, and waiting for a clone means the operator can
// stare at an empty pane while a large repository downloads.
func TestSearchHitsAreSurfacedImmediately(t *testing.T) {
	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"ipregionchecker.org"`: {
			{Repo: "stockx-fi/stockx_v1", Path: "backend/src/compliance/complianceService.js"},
		},
	}}
	// No analyzer result: the repo never yields clone-based findings.
	an := &fakeAnalyzer{byRepo: map[string]Analysis{}}

	bus := event.NewBus()
	done := collect(bus)
	e := NewEngine(gh, an, bus, Options{Indicators: []string{"ipregionchecker.org"}, Budget: DefaultBudget()})
	e.Run(context.Background())

	var found bool
	for _, ev := range done() {
		if ev.Kind == event.KindFinding && ev.Repo == "stockx-fi/stockx_v1" {
			found = true
			if ev.Path == "" {
				t.Error("a search hit must carry the file path")
			}
			if ev.URL == "" {
				t.Error("a search hit must carry a link to the file")
			}
		}
	}
	if !found {
		t.Fatal("the code-search hit was never surfaced as a finding")
	}
}

// One enormous repository must not silently consume the crawl.
func TestOversizedRepoIsRefusedAndReported(t *testing.T) {
	big := &ghapi.RepoMeta{FullName: "huge/monorepo", Size: 8 << 20} // 8 GB
	gh := &fakeGH{
		search: map[string][]ghapi.CodeHit{`"x.example"`: {{Repo: "huge/monorepo", Path: "a.js"}}},
		meta:   map[string]*ghapi.RepoMeta{"huge/monorepo": big},
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"huge/monorepo": {Findings: []criteria.Finding{{Signal: "x", Tier: criteria.TierA}}},
	}}

	bus := event.NewBus()
	done := collect(bus)
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"x.example"}, Budget: DefaultBudget(), MaxRepoKB: 1 << 20,
	})
	e.Run(context.Background())

	var told bool
	for _, ev := range done() {
		if strings.Contains(ev.Message, "NOT ANALYSED") {
			told = true
		}
	}
	if !told {
		t.Error("skipping a repository for size must be reported, not silent")
	}
}

// A threat-intel feed carries the campaign's domains without naming itself.
// It must be recognised from the shape of the evidence, before the clone.
func TestFeedRepoClassifiedBeforeClone(t *testing.T) {
	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"evil.example.org"`: {{Repo: "0xDanielLopez/TweetFeed", Path: "2026/202606/20260630.csv"}},
	}}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"0xDanielLopez/TweetFeed": {
			Findings: []criteria.Finding{{Signal: "ioc-domain", Tier: criteria.TierA}},
			Authors:  []Identity{{Name: "Feed Maintainer", Email: "m@x.io"}},
		},
	}}

	bus := event.NewBus()
	done := collect(bus)
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"}, Budget: DefaultBudget(),
		NoBuiltinIndicators: true,
	})
	e.Run(context.Background())

	if _, ok := e.Graph().Get(graph.ID(graph.KindIdentity, "Feed Maintainer <m@x.io>")); ok {
		t.Error("a feed maintainer must not be expanded as a campaign identity")
	}
	if n := len(e.MaliciousRepos()); n != 0 {
		t.Errorf("malicious repos = %d, want 0: a blocklist is not compromised", n)
	}
	var told bool
	for _, ev := range done() {
		if strings.Contains(ev.Message, "documents the campaign") {
			told = true
		}
	}
	if !told {
		t.Error("the operator should be told the feed was skipped and why")
	}
}

// A campaign address in a config file the program reads keeps its tier; the same
// match in prose is capped. Both arrive through the search index here, which is
// the path that records a finding before any clone.
func TestSearchHitTierCapFollowsRecordOnlyPaths(t *testing.T) {
	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"evil.example.org"`: {
			{Repo: "victim/app", Path: "src/config.json"},
			{Repo: "writer/blog", Path: "README.md"},
		},
	}}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"}, Budget: DefaultBudget(),
		NoBuiltinIndicators: true,
	})
	e.Run(context.Background())

	first := func(repo string) criteria.Finding {
		n, ok := e.Graph().Get(graph.ID(graph.KindRepo, repo))
		if !ok || len(n.Findings) == 0 {
			t.Fatalf("%s has no recorded finding", repo)
		}
		return n.Findings[0]
	}
	if f := first("victim/app"); f.Tier != criteria.TierA || f.Documentary {
		t.Errorf("config.json hit: tier %v documentary %v, want uncapped Tier A", f.Tier, f.Documentary)
	}
	if f := first("writer/blog"); f.Tier != criteria.TierC || !f.Documentary {
		t.Errorf("README.md hit: tier %v documentary %v, want capped Tier C", f.Tier, f.Documentary)
	}
}

// The same check must not swallow a victim whose payload sits in settings.json.
func TestVictimWithJSONPayloadStillAnalysed(t *testing.T) {
	gh := &fakeGH{search: map[string][]ghapi.CodeHit{
		`"evil.example.org"`: {{Repo: "candidate/assessment", Path: ".vscode/settings.json"}},
	}}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"candidate/assessment": {
			Findings: []criteria.Finding{
				{Signal: "vscode-terminal-hijack", Tier: criteria.TierB, Path: ".vscode/settings.json"},
				{Signal: "ioc-domain", Tier: criteria.TierA, Path: ".vscode/settings.json"},
			},
		},
	}}

	bus := event.NewBus()
	defer bus.Close()
	e := NewEngine(gh, an, bus, Options{
		Indicators: []string{"evil.example.org"}, Budget: DefaultBudget(),
		NoBuiltinIndicators: true,
	})
	e.Run(context.Background())

	if n := len(e.MaliciousRepos()); n != 1 {
		t.Errorf("malicious repos = %d, want 1: settings.json is JSON and still executes", n)
	}
}

// --repo mode examines exactly the named repository: no canary, no search, no
// expansion to the authors of what it finds, and no corpus exemption.
func TestTargetRepoScansOnlyThatRepository(t *testing.T) {
	gh := &fakeGH{
		identity: map[string][]string{"Op Persona|op@mail.invalid": {"operator/other"}},
		// A name the corpus heuristics would normally skip.
		meta: map[string]*ghapi.RepoMeta{
			"someone/ioc-blocklist": {FullName: "someone/ioc-blocklist", Description: "malware IOC feed"},
		},
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"someone/ioc-blocklist": {
			Findings: []criteria.Finding{{
				Signal: "remote-eval", Tier: criteria.TierB, Subject: criteria.SubjectFile,
				Repo: "someone/ioc-blocklist", Path: "a.js", Evidence: "eval(res.data)",
			}},
			Authors: []Identity{{Name: "Op Persona", Email: "op@mail.invalid"}},
		},
	}}
	bus := event.NewBus()
	drain := collect(bus)
	e := NewEngine(gh, an, bus, Options{
		TargetRepo: "someone/ioc-blocklist",
		Budget:     DefaultBudget(),
	})
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	drain()

	if len(gh.searches) != 0 {
		t.Errorf("single-repo mode searched: %v", gh.searches)
	}
	n, ok := e.Graph().Get(graph.ID(graph.KindRepo, "someone/ioc-blocklist"))
	if !ok || !n.Examined || n.Corpus || len(n.Findings) == 0 {
		t.Fatalf("target should be examined with findings, got %+v", n)
	}
	if _, ok := e.Graph().Get(graph.ID(graph.KindRepo, "operator/other")); ok {
		t.Error("single-repo mode must not follow authors to other repositories")
	}
	if len(e.Graph().Nodes()) != 1 {
		t.Errorf("graph has %d nodes, want 1", len(e.Graph().Nodes()))
	}
}

// A repository that warns about itself is still analysed and kept, but it is
// marked as self-declared and nothing is expanded from it.
func TestWarnedRepositoryIsMarkedAndNotExpanded(t *testing.T) {
	gh := &fakeGH{
		readme: map[string]string{
			"res/real-world-assets": "THIS REPO CONTAINS MALICIOS CODE it is here for investigation purposes only. DO NOT DOWNLOAD OR RUN THIS CODE",
		},
		identity: map[string][]string{"Op Persona|op@mail.invalid": {"operator/other"}},
	}
	an := &fakeAnalyzer{byRepo: map[string]Analysis{
		"res/real-world-assets": {
			Findings: []criteria.Finding{{
				Signal: "vscode-terminal-hijack", Tier: criteria.TierA, Subject: criteria.SubjectFile,
				Repo: "res/real-world-assets", Path: ".vscode/settings.json", Evidence: "curl x | sh",
			}},
			Authors: []Identity{{Name: "Op Persona", Email: "op@mail.invalid"}},
		},
	}}
	bus := event.NewBus()
	drain := collect(bus)
	e := NewEngine(gh, an, bus, Options{TargetRepo: "res/real-world-assets", Budget: DefaultBudget()})
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	drain()

	n, ok := e.Graph().Get(graph.ID(graph.KindRepo, "res/real-world-assets"))
	if !ok || !n.Warned || !n.Examined || len(n.Findings) == 0 {
		t.Fatalf("want warned, examined, findings kept; got %+v", n)
	}
	if _, ok := e.Graph().Get(graph.ID(graph.KindIdentity, "Op Persona <op@mail.invalid>")); ok {
		t.Error("a self-declared research copy must not be expanded to its authors")
	}
	if st := e.Graph().Stats(); st.Malicious != 0 {
		t.Errorf("Stats.Malicious = %d, a warned repository must not be counted", st.Malicious)
	}
}
