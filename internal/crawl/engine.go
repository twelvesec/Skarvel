package crawl

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"skarvel/internal/bbapi"
	"skarvel/internal/criteria"
	"skarvel/internal/event"
	"skarvel/internal/ghapi"
	"skarvel/internal/graph"
	"skarvel/internal/guard"
	"skarvel/internal/indicator"
	"skarvel/internal/model"
)

// GitHub is the platform surface the engine needs.
//
// An interface rather than a concrete client so the expansion logic -- the part
// that implements tool.md and therefore the part most worth testing -- can be
// exercised without a network or a token.
type GitHub interface {
	ListRepos(ctx context.Context, owner string) ([]model.Repo, error)
	GetRepo(ctx context.Context, fullName string) (*ghapi.RepoMeta, error)
	GetReadme(ctx context.Context, fullName string, maxBytes int) (string, error)
	SearchCode(ctx context.Context, query string, maxPages int) ([]ghapi.CodeHit, int, error)
	ReposForIdentity(ctx context.Context, name, email string) ([]string, error)
}

// Platform is the GitHub interface under the name it deserves now that a
// second hosting platform (Bitbucket Cloud, internal/bbapi) implements it.
type Platform = GitHub

// CanaryProvider is optionally implemented by a platform whose search backend
// does not need the GitHub canary. GitHub answers an unsupported qualifier
// with zero results, which is why a known-good query must pass before any
// zero can be trusted; a backend that errors instead has no such failure mode.
// The platform states its reason, and the engine records it in the log so the
// decision to skip the probe is never silent.
type CanaryProvider interface {
	Canary() (query string, needed bool, why string)
}

// Analysis is what examining one repository produced.
type Analysis struct {
	Findings   []criteria.Finding
	Timestamps criteria.TimestampResult

	// Authors are the identities behind flagged commits. Expansion follows
	// these, never the repository owner -- the owner may be the victim of the
	// push (tool.md section 2).
	Authors []Identity

	Candidates []indicator.Indicator
	Skipped    string // non-empty when the repo was deliberately not analysed
}

// Identity is a git author identity, which is not a platform account.
type Identity struct {
	Name  string
	Email string
}

func (i Identity) Key() string { return i.Name + " <" + i.Email + ">" }

// Analyzer examines one repository.
type Analyzer interface {
	Analyze(ctx context.Context, repo string, meta *ghapi.RepoMeta, inds *indicator.Set) (Analysis, error)
}

// Options configure a crawl.
type Options struct {
	Seed        string   // seed username, may be empty when seeding on indicators alone
	Indicators  []string // seed indicator strings, treated as confirmed
	Budget      *Budget
	SearchPages int

	// AutoPromote allows mined network locators to become search seeds without
	// review. Generic strings are never auto-promoted regardless.
	AutoPromote bool

	// FollowLeads permits the cold-start pass over Tier-D identity leads once
	// the evidential frontier is dry.
	FollowLeads bool

	// MaxRepoKB refuses to clone repositories above this size. Zero disables
	// the check.
	MaxRepoKB int

	// NoBuiltinIndicators suppresses the confirmed campaign infrastructure that
	// is otherwise seeded on every run (indicator.Known).
	NoBuiltinIndicators bool

	// Platform is the host every repository key refers to: criteria.HostGitHub
	// (the default when empty) or criteria.HostBitbucket. It is stamped on
	// each finding so permalinks point at the right site.
	Platform string

	// TargetRepo, when set, restricts the run to examining this one repository
	// ("owner/name"): no code search, no canary, no expansion to accounts,
	// identities or mined indicators. The analyst named the repository, so the
	// corpus heuristics that normally skip documentation repositories are not
	// applied either. Indicators, if any, are still matched inside it.
	TargetRepo string
}

// Engine runs the expansion loop.
type Engine struct {
	gh   GitHub
	an   Analyzer
	bus  *event.Bus
	g    *graph.Graph
	f    *Frontier
	inds *indicator.Set
	opt  Options

	mu       sync.Mutex
	review   []criteria.Finding    // person-level findings awaiting sign-off
	queued   []indicator.Indicator // indicators awaiting sign-off
	promoted []indicator.Indicator // mined indicators that became search seeds
	canaryOK bool

	// repoErr is why the single target repository could not be examined.
	repoErr string

	// Searches that failed or could not be trusted. A crawl whose searches
	// fail finds nothing, and "nothing" must never be reported as clean.
	searchFailed     int
	searchUnverified int
	lastSearchErr    string

	// forgedBy records which repositories with fabricated history each identity
	// appears in. An identity reused across two or more such repositories is
	// the operator's own selection signal -- they pick names whose credibility
	// makes planted code look accredited -- which makes it a lead worth
	// following and never, on its own, an accusation (tool.md section 9).
	forgedBy map[string]map[string]bool
}

func NewEngine(gh GitHub, an Analyzer, bus *event.Bus, opt Options) *Engine {
	if opt.Budget == nil {
		opt.Budget = DefaultBudget()
	}
	if opt.SearchPages <= 0 {
		opt.SearchPages = 2
	}
	if opt.MaxRepoKB == 0 {
		opt.MaxRepoKB = 2 << 20 // 2 GB
	}
	inds := indicator.NewSet()
	if !opt.NoBuiltinIndicators {
		// Confirmed infrastructure is searched every run without being asked
		// for: the operator reuses it across lures, and requiring an analyst to
		// remember each domain is how a known C2 gets missed.
		for _, in := range indicator.Known {
			inds.Add(in)
		}
	}
	for _, v := range opt.Indicators {
		inds.Add(indicator.Indicator{
			Value: v, Kind: classify(v), Source: "seed", Confirmed: true,
		})
		// An encoded IOC is also hunted in its decoded form: the same endpoint
		// is routinely committed raw in one repository and base64-wrapped in
		// the next, and code search matches only the literal text it is given.
		for _, d := range indicator.Decode(v) {
			inds.Add(indicator.Indicator{
				Value: d, Kind: classify(d), Source: "seed (decoded)", Confirmed: true,
			})
		}
	}
	return &Engine{
		gh: gh, an: an, bus: bus, opt: opt,
		g: graph.New(), f: NewFrontier(), inds: inds,
		forgedBy: map[string]map[string]bool{},
	}
}

func classify(v string) indicator.Kind {
	switch {
	case strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://"):
		return indicator.KindURL
	case strings.Count(v, ".") == 3 && strings.IndexFunc(v, func(r rune) bool {
		return r != '.' && r != ':' && (r < '0' || r > '9')
	}) < 0:
		return indicator.KindIP
	case strings.Contains(v, "."):
		return indicator.KindDomain
	}
	return indicator.KindGeneric
}

func (e *Engine) Graph() *graph.Graph { return e.g }

// Platform returns the host this crawl runs against.
func (e *Engine) Platform() string {
	if e.opt.Platform == "" {
		return criteria.HostGitHub
	}
	return e.opt.Platform
}

// platformLabel is the human name used in messages.
func (e *Engine) platformLabel() string {
	if e.Platform() == criteria.HostBitbucket {
		return "Bitbucket"
	}
	return "GitHub"
}

// stamp sets the platform host on findings so their permalinks resolve.
func (e *Engine) stamp(fs []criteria.Finding) []criteria.Finding {
	host := e.Platform()
	for i := range fs {
		if fs[i].Host == "" {
			fs[i].Host = host
		}
	}
	return fs
}

// noteSearchError records a search that did not run to completion.
func (e *Engine) noteSearchError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.searchFailed++
	e.lastSearchErr = err.Error()
}

// SearchProblems reports how many searches failed outright, how many returned
// zero results that cannot be trusted (the canary never passed), and the most
// recent failure.
func (e *Engine) SearchProblems() (failed, unverified int, last string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.searchFailed, e.searchUnverified, e.lastSearchErr
}

// Review returns the person-level findings held for sign-off.
func (e *Engine) Review() []criteria.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]criteria.Finding(nil), e.review...)
}

// QueuedIndicators returns mined indicators awaiting approval.
func (e *Engine) QueuedIndicators() []indicator.Indicator {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]indicator.Indicator(nil), e.queued...)
}

// NewIndicators reports what the hunt learned, for the report.
//
// promoted are the indicators mined from confirmed payloads that were added to
// the search set; candidates are the ones held back for an analyst's decision,
// de-duplicated and without anything already in the search set (a built-in or
// seed indicator re-found in a second file is not news).
func (e *Engine) NewIndicators() (promoted, candidates []indicator.Indicator) {
	e.mu.Lock()
	defer e.mu.Unlock()

	promoted = append(promoted, e.promoted...)
	seen := map[string]bool{}
	for _, c := range e.queued {
		k := strings.ToLower(c.Value)
		if seen[k] || e.inds.Has(c.Value) {
			continue
		}
		seen[k] = true
		candidates = append(candidates, c)
	}
	return promoted, candidates
}

// Run executes the crawl until the budget is spent or the search goes dry.
func (e *Engine) Run(ctx context.Context) error {
	e.opt.Budget.Start()

	if e.opt.TargetRepo != "" {
		return e.runSingle(ctx)
	}

	// The canary must pass before any zero-result search is trusted.
	if err := e.checkCanary(ctx); err != nil {
		return err
	}

	e.seed()

	for round := 1; ; round++ {
		if ctx.Err() != nil {
			e.bus.Emit(event.Event{Kind: event.KindHalt, Message: "cancelled"})
			return ctx.Err()
		}
		if e.opt.Budget.Expired() {
			e.bus.Emit(event.Event{Kind: event.KindHalt, Message: e.opt.Budget.StopReason()})
			break
		}

		it := e.f.Pop()
		if it == nil {
			dry := e.f.EndRound()
			e.bus.Emit(event.Event{Kind: event.KindRound, Score: round,
				Message: fmt.Sprintf("round %d closed, queue empty", round)})
			if dry {
				// Cold start: only now, and only if permitted, are identity
				// leads followed -- and everything they yield stays a lead.
				if e.opt.FollowLeads && e.f.PendingLeads() > 0 {
					n := e.f.ReleaseLeads()
					e.bus.Emit(event.Event{Kind: event.KindLog, Message: fmt.Sprintf(
						"evidential frontier dry; releasing %d identity lead(s). "+
							"Anything found this way is a lead, not evidence.", n)})
					continue
				}
				e.bus.Emit(event.Event{Kind: event.KindDone,
					Message: "search dry: two consecutive rounds admitted nothing above the expansion threshold"})
				break
			}
			continue
		}

		if !e.opt.Budget.DepthOK(it.Hops) {
			continue
		}
		e.visit(ctx, it)
	}

	e.emitSummary()
	return nil
}

// runSingle examines the one repository named in Options.TargetRepo.
func (e *Engine) runSingle(ctx context.Context) error {
	repo := e.opt.TargetRepo
	e.g.AddSeed(graph.KindRepo, repo)
	id := graph.ID(graph.KindRepo, repo)
	e.bus.Emit(event.Event{Kind: event.KindDiscover, Node: repo,
		NodeKind: "repo", Message: "target repository"})
	e.visit(ctx, &Item{NodeID: id, Kind: graph.KindRepo, Score: 100})
	e.emitSummary()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e.repoErr != "" {
		return errors.New(e.repoErr)
	}
	return nil
}

func (e *Engine) checkCanary(ctx context.Context) error {
	c := guard.DefaultCanary()
	if cp, ok := e.gh.(CanaryProvider); ok {
		q, needed, why := cp.Canary()
		if !needed {
			e.canaryOK = true
			e.bus.Logf("search canary skipped on %s: %s; zero-result queries can be trusted", e.platformLabel(), why)
			return nil
		}
		if q != "" {
			c.Query = q
		}
	}
	if !e.opt.Budget.SpendSearch(1) {
		return fmt.Errorf("search budget exhausted before the canary could run")
	}
	_, total, err := e.gh.SearchCode(ctx, c.Query, 1)
	if err != nil {
		// A hard error is honest; it is a silent zero that is dangerous.
		e.noteSearchError(err)
		e.bus.Logf("canary query errored (%v); continuing, but zero-result searches will be reported as unverified", err)
		return nil
	}
	ok, why := guard.CheckCanary(c, total)
	if !ok {
		e.opt.Budget.Halt(why)
		e.bus.Emit(event.Event{Kind: event.KindHalt, Message: why})
		return fmt.Errorf("%s", why)
	}
	e.canaryOK = true
	e.bus.Logf("search canary ok (%d results); zero-result queries can be trusted", total)
	return nil
}

func (e *Engine) seed() {
	if e.opt.Seed != "" {
		e.g.AddSeed(graph.KindAccount, e.opt.Seed)
		e.f.Push(&Item{
			NodeID: graph.ID(graph.KindAccount, e.opt.Seed),
			Kind:   graph.KindAccount, Score: 100, Hops: 0,
		})
		e.bus.Emit(event.Event{Kind: event.KindDiscover, Node: e.opt.Seed,
			NodeKind: "account", Message: "seed account"})
	}
	for _, in := range e.inds.All() {
		e.g.AddSeed(graph.KindIndicator, in.Value)
		e.f.Push(&Item{
			NodeID: graph.ID(graph.KindIndicator, in.Value),
			Kind:   graph.KindIndicator, Score: 100, Hops: 0,
		})
		e.bus.Emit(event.Event{Kind: event.KindDiscover, Node: in.Value,
			NodeKind: "indicator", Message: "seed indicator (" + in.Kind.String() + ")"})
	}
}

func (e *Engine) visit(ctx context.Context, it *Item) {
	e.g.MarkVisited(it.NodeID)
	n, ok := e.g.Get(it.NodeID)
	if !ok {
		return
	}
	e.bus.Emit(event.Event{Kind: event.KindVisit, Node: n.Key, NodeKind: n.Kind.String(),
		Hops: n.Hops, Score: n.Score, Lead: n.Lead})

	switch n.Kind {
	case graph.KindAccount:
		e.visitAccount(ctx, it, *n)
	case graph.KindIndicator:
		e.visitIndicator(ctx, it, *n)
	case graph.KindRepo:
		e.visitRepo(ctx, it, *n)
	case graph.KindIdentity:
		e.visitIdentity(ctx, it, *n)
	}
}

func (e *Engine) visitAccount(ctx context.Context, it *Item, n graph.Node) {
	if !e.opt.Budget.SpendAPI(2) {
		return
	}
	repos, err := e.gh.ListRepos(ctx, n.Key)
	if err != nil {
		e.bus.Logf("list repos for %s: %v", n.Key, err)
		return
	}
	for _, r := range repos {
		e.discoverRepo(it.NodeID, r.FullName, "account-repos", criteria.TierB, n.Lead, n.Hops)
	}
}

// visitIndicator is the flywheel: a confirmed string finds repositories that
// have no social connection to the seed at all.
func (e *Engine) visitIndicator(ctx context.Context, it *Item, n graph.Node) {
	if !e.opt.Budget.SpendSearch(1) {
		return
	}
	hits, total, err := e.gh.SearchCode(ctx, "\""+n.Key+"\"", e.opt.SearchPages)
	if err != nil {
		e.noteSearchError(err)
		e.bus.Logf("code search %q: %v", n.Key, err)
		return
	}
	if total == 0 && !e.canaryOK {
		e.mu.Lock()
		e.searchUnverified++
		e.mu.Unlock()
		e.bus.Logf("search for %q returned zero, but the canary never passed: "+
			"treating as UNVERIFIED rather than absent", n.Key)
		return
	}
	e.bus.Logf("indicator %q: %d code hits", n.Key, total)

	// Surface every hit immediately. The search index already gives repository
	// and path, and waiting for a clone to confirm them means the operator
	// stares at an empty findings pane while a large repository downloads --
	// or never sees the hit at all if that repository turns out to be a corpus
	// and is skipped. The line number arrives later, from the clone.
	seen := map[string]bool{}
	for _, h := range hits {
		if !seen[h.Repo] {
			seen[h.Repo] = true
			e.discoverRepo(it.NodeID, h.Repo, "indicator-match", criteria.TierA, n.Lead, n.Hops)
		}

		// Recorded on the node, not merely emitted: the screen scrolls and the
		// report is what survives. A repository that is later skipped -- as a
		// corpus, or for size -- would otherwise leave no trace of the hit
		// anywhere durable.
		f := criteria.CapDocumentaryTier(criteria.Finding{
			Signal: "indicator-code-search", Tier: criteria.TierA,
			Subject: criteria.SubjectFile, Repo: h.Repo, Path: h.Path,
			Why:      e.platformLabel() + " code search matched indicator " + n.Key,
			Evidence: n.Key, Host: e.Platform(),
		}, guard.IsRecordOnly(h.Path))
		rid := graph.ID(graph.KindRepo, h.Repo)
		e.g.RecordFindings(rid, []criteria.Finding{f})

		// Classify now, not only at visit time. With a repository budget in
		// force most discovered repositories are never visited, and without
		// this they would carry a verdict derived from a single search-index
		// hit and no examination at all.
		if rn, ok := e.g.Get(rid); ok && !rn.Corpus {
			if cv := guard.ClassifyCorpus(h.Repo, "", "", nil, false); cv.IsCorpus {
				e.markCorpus(rid, h.Repo, cv.Reason)
			} else if cv := guard.ClassifyByEvidence(matchedPaths(rn)); cv.IsCorpus {
				e.markCorpus(rid, h.Repo, cv.Reason)
			}
		}
		e.bus.Emit(event.Event{
			Kind: event.KindFinding, Repo: h.Repo, Path: h.Path,
			Signal: f.Signal, Tier: f.Tier.String(), Evidence: f.Evidence,
			URL:  f.URL(),
			Node: h.Repo, NodeKind: "repo", Lead: n.Lead,
			Message: "search-index hit; line number follows after clone",
		})
	}
}

func (e *Engine) visitIdentity(ctx context.Context, it *Item, n graph.Node) {
	name, email := splitIdentity(n.Key)
	if !e.opt.Budget.SpendSearch(1) {
		return
	}
	repos, err := e.gh.ReposForIdentity(ctx, name, email)
	if err != nil {
		// Bitbucket has no cross-repository commit search; that gap is a
		// documented property of the platform, not a failed search.
		if !errors.Is(err, bbapi.ErrUnsupported) {
			e.noteSearchError(err)
		}
		e.bus.Logf("repos for identity %s: %v", n.Key, err)
		return
	}
	for _, r := range repos {
		e.discoverRepo(it.NodeID, r, "authored-commits", criteria.TierB, n.Lead, n.Hops)
	}
}

func (e *Engine) visitRepo(ctx context.Context, it *Item, n graph.Node) {
	if !e.opt.Budget.SpendRepo() {
		return
	}
	if !e.opt.Budget.SpendAPI(3) {
		return
	}

	node, _ := e.g.Get(it.NodeID)

	meta, err := e.gh.GetRepo(ctx, n.Key)
	if err != nil {
		e.bus.Logf("repo meta %s: %v", n.Key, err)
		e.repoErr = fmt.Sprintf("cannot read repository %s: %v", n.Key, err)
		return
	}
	readme, _ := e.gh.GetReadme(ctx, n.Key, 4096)

	single := e.opt.TargetRepo != ""

	// A research corpus is saturated with exactly the signals this tool hunts.
	// Record it, never expand it. (Skipped for a repository the analyst named.)
	if cv := guard.ClassifyCorpus(n.Key, meta.Description, readme, meta.Topics, meta.Fork); cv.IsCorpus && !single {
		e.markCorpus(it.NodeID, n.Key, cv.Reason)
		return
	}

	// Evidence-shape check, using the paths the code search already matched.
	// Threat-intelligence feeds carry campaign domains without announcing
	// themselves in a name or topic, and this runs BEFORE the clone so a
	// catalogue costs nothing to recognise.
	if cv := guard.ClassifyByEvidence(matchedPaths(node)); cv.IsCorpus && !single {
		e.markCorpus(it.NodeID, n.Key, cv.Reason)
		return
	}

	// The owner's own warning ("contains malicious code, do not run") marks a
	// research or victim copy of a lure. It is still analysed -- the claim is
	// unverified and an operator can write the same sentence -- but it is
	// reported in its own section and never expanded from.
	warned := false
	if w := guard.DetectWarning(meta.Description, readme); w.Found {
		warned = true
		e.g.MarkWarned(it.NodeID, w.Quote)
		e.bus.Logf("%s: owner's notice says it holds malicious code (%q); "+
			"reported as self-declared, not as confirmed", n.Key, w.Quote)
	}

	// A single very large repository can consume the entire crawl: the clone
	// dominates wall-clock and disk while everything else waits. Refusing it is
	// a deliberate, logged gap rather than a silent one.
	if e.opt.MaxRepoKB > 0 && meta.Size > e.opt.MaxRepoKB {
		e.bus.Emit(event.Event{Kind: event.KindLog, Repo: n.Key, Message: fmt.Sprintf(
			"NOT ANALYSED: %d MB exceeds the %d MB clone limit",
			meta.Size/1024, e.opt.MaxRepoKB/1024)})
		e.repoErr = fmt.Sprintf("%s is %d MB, over the %d MB clone limit", n.Key, meta.Size/1024, e.opt.MaxRepoKB/1024)
		return
	}

	an, err := e.an.Analyze(ctx, n.Key, meta, e.inds)
	if err != nil {
		e.bus.Logf("analyse %s: %v", n.Key, err)
		e.repoErr = fmt.Sprintf("cannot analyse %s: %v", n.Key, err)
		return
	}
	if an.Skipped != "" {
		e.repoErr = fmt.Sprintf("%s was skipped: %s", n.Key, an.Skipped)
		e.bus.Emit(event.Event{Kind: event.KindLog, Repo: n.Key, Message: "skipped: " + an.Skipped})
		return
	}
	e.g.MarkExamined(it.NodeID)

	findings := an.Findings
	if f, ok := an.Timestamps.ToFinding(n.Key); ok {
		findings = append(findings, f)
	}
	findings = e.stamp(findings)

	fresh := e.g.RecordFindings(it.NodeID, findings)
	node, _ = e.g.Get(it.NodeID)
	a := criteria.Assess(node.Findings)

	for _, f := range findings {
		e.bus.Emit(event.Event{
			Kind: event.KindFinding, Repo: n.Key, Path: f.Path, Line: f.Line,
			Signal: f.Signal, Tier: f.Tier.String(), Evidence: f.Evidence,
			URL:  f.URL(),
			Node: n.Key, NodeKind: "repo", Lead: n.Lead,
			Chain: e.g.ChainString(it.NodeID), Message: f.Why,
		})
	}
	verdict := a.Verdict.String()
	if warned && a.Verdict != criteria.VerdictClean {
		verdict = "WARNED"
	}
	e.bus.Emit(event.Event{Kind: event.KindVerdict, Repo: n.Key, Node: n.Key,
		NodeKind: "repo", Verdict: verdict, Score: a.Score, Lead: n.Lead,
		Message: a.Reason, Chain: e.g.ChainString(it.NodeID)})
	if warned {
		// Nothing learned from a self-declared research copy is followed or
		// mined: its authors are usually the victim or the analyst.
		return
	}

	// Identities appearing in fabricated history are tracked across repos. The
	// same name being reused is the operator's selection at work, not chance.
	if an.Timestamps.Tier == criteria.TierB {
		for _, id := range an.Authors {
			e.noteForgedIdentity(it.NodeID, id, n)
		}
	}

	// Person-level conclusions are queued rather than published: three real
	// developers were impersonated in the campaign this tool was built from.
	for _, l := range a.Leads {
		e.mu.Lock()
		e.review = append(e.review, l)
		e.mu.Unlock()
		e.bus.Emit(event.Event{Kind: event.KindReview, Repo: n.Key, Signal: l.Signal,
			Message: "identity lead held for review (not an accusation): " + l.Why})
	}

	if fresh == 0 && len(findings) > 0 {
		e.bus.Logf("%s: all findings already seen elsewhere (fork or copy), not counted again", n.Key)
	}

	if !a.Expand || single {
		return
	}

	// Expansion follows authorship -- but only where authorship means anything.
	//
	// Git author metadata is unauthenticated, and in a repository whose history
	// has been fabricated it is precisely the thing being forged: the payload is
	// attributed to the developer whose name lends it credibility. Expanding on
	// it there would walk the crawler straight into the victim's other projects,
	// which is the exact outcome Tier D exists to prevent. A fabricated history
	// therefore invalidates its own attribution, and those identities are raised
	// as leads instead (see noteForgedIdentity).
	if an.Timestamps.Tier == criteria.TierB {
		e.bus.Emit(event.Event{Kind: event.KindLog, Repo: n.Key, Message: fmt.Sprintf(
			"history is fabricated; not expanding on its %d author identity(ies) — "+
				"forged commits name whoever the operator chose to impersonate",
			len(an.Authors))})
	} else {
		for _, id := range an.Authors {
			e.discoverIdentity(it.NodeID, id, "authored-flagged-commit", criteria.TierB, n.Lead, n.Hops)
		}
	}

	// Mine new indicators only from a repository that is actually confirmed.
	confirmed := a.Verdict == criteria.VerdictMalicious
	for _, cand := range an.Candidates {
		// Re-finding something already being hunted (the seed itself, a built-in)
		// is not a discovery, and must not be reported as one.
		if e.inds.Has(cand.Value) {
			continue
		}
		auto, queued := indicator.Promote(cand, confirmed)
		switch {
		case auto && e.opt.AutoPromote:
			cand.Confirmed = true
			e.inds.Add(cand)
			e.mu.Lock()
			e.promoted = append(e.promoted, cand)
			e.mu.Unlock()
			e.g.Discover(it.NodeID, graph.KindIndicator, cand.Value, "mined-indicator", criteria.TierA, n.Lead)
			e.f.Push(&Item{
				NodeID: graph.ID(graph.KindIndicator, cand.Value),
				Kind:   graph.KindIndicator, Score: 100, Hops: n.Hops + 1, Lead: n.Lead,
			})
			e.bus.Emit(event.Event{Kind: event.KindIndicator, Repo: n.Key,
				Message: "promoted " + cand.Kind.String() + " indicator " + cand.Value})
		case auto || queued:
			e.mu.Lock()
			e.queued = append(e.queued, cand)
			e.mu.Unlock()
			e.bus.Emit(event.Event{Kind: event.KindIndicator, Repo: n.Key,
				Message: "queued for review: " + cand.Kind.String() + " " + cand.Value})
		}
	}
}

// noteForgedIdentity records an identity seen in fabricated history and, on the
// second distinct repository, raises it as a Tier-D lead.
//
// One appearance is meaningless -- someone has to be the author of record. Two
// separate fabricated histories carrying the same name is the operator reusing
// a persona or reusing a borrowed reputation, and either is worth a look.
func (e *Engine) noteForgedIdentity(from string, id Identity, n graph.Node) {
	key := id.Key()

	e.mu.Lock()
	if e.forgedBy[key] == nil {
		e.forgedBy[key] = map[string]bool{}
	}
	e.forgedBy[key][n.Key] = true
	count := len(e.forgedBy[key])
	repos := make([]string, 0, count)
	for r := range e.forgedBy[key] {
		repos = append(repos, r)
	}
	e.mu.Unlock()

	if count < 2 {
		return
	}
	sort.Strings(repos)

	lead := criteria.Finding{
		Signal:   "identity-in-fabricated-history",
		Tier:     criteria.TierD,
		Subject:  criteria.SubjectIdentity,
		Identity: key,
		Repo:     n.Key,
		Why: "this identity is the author of record in fabricated commit history in " +
			fmt.Sprintf("%d repositories (%s). Impersonation targets are chosen for "+
				"credibility, so the named person is more likely a victim than an "+
				"operator. Lead only -- contributes nothing to any verdict.",
				count, strings.Join(repos, ", ")),
	}

	e.mu.Lock()
	e.review = append(e.review, lead)
	e.mu.Unlock()

	e.bus.Emit(event.Event{Kind: event.KindReview, Repo: n.Key, Signal: lead.Signal,
		Node: key, NodeKind: "identity", Lead: true, Message: lead.Why})

	// Queued as a lead: held out of the frontier entirely until the evidential
	// search is exhausted, and only then if --follow-leads was given.
	if _, isNew := e.g.Discover(from, graph.KindIdentity, key, "identity-lead", criteria.TierD, true); isNew {
		e.f.Push(&Item{
			NodeID: graph.ID(graph.KindIdentity, key), Kind: graph.KindIdentity,
			Score: 0, Hops: n.Hops + 1, Lead: true,
		})
	}
}

// markCorpus records a repository as documenting the campaign and tells the
// operator why, so a skip is never silent.
func (e *Engine) markCorpus(id, repo, reason string) {
	e.g.MarkCorpus(id, reason)
	e.bus.Emit(event.Event{Kind: event.KindLog, Repo: repo, Node: repo, NodeKind: "repo",
		Message: "not expanded (documents the campaign rather than carrying it): " + reason})
}

// matchedPaths lists the file paths a node's findings point at.
func matchedPaths(n *graph.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, f := range n.Findings {
		if f.Path != "" {
			out = append(out, f.Path)
		}
	}
	return out
}

func (e *Engine) discoverRepo(from, full, reason string, tier criteria.Tier, lead bool, hops int) {
	n, isNew := e.g.Discover(from, graph.KindRepo, full, reason, tier, lead)
	if !isNew {
		return
	}
	e.f.Push(&Item{
		NodeID: graph.ID(graph.KindRepo, full), Kind: graph.KindRepo,
		Score: tier.Score(), Hops: n.Hops, Lead: n.Lead,
	})
	e.bus.Emit(event.Event{Kind: event.KindDiscover, Node: full, NodeKind: "repo",
		Hops: n.Hops, Lead: n.Lead, Message: reason})
}

func (e *Engine) discoverIdentity(from string, id Identity, reason string, tier criteria.Tier, lead bool, hops int) {
	n, isNew := e.g.Discover(from, graph.KindIdentity, id.Key(), reason, tier, lead)
	if !isNew {
		return
	}
	e.f.Push(&Item{
		NodeID: graph.ID(graph.KindIdentity, id.Key()), Kind: graph.KindIdentity,
		Score: tier.Score(), Hops: n.Hops, Lead: n.Lead,
	})
	e.bus.Emit(event.Event{Kind: event.KindDiscover, Node: id.Key(), NodeKind: "identity",
		Hops: n.Hops, Lead: n.Lead, Message: reason})
}

func (e *Engine) emitSummary() {
	st := e.g.Stats()
	e.bus.Emit(event.Event{Kind: event.KindDone, Score: st.Malicious, Message: fmt.Sprintf(
		"%d nodes, %d visited, %d malicious, %d review, %d leads, %d distinct findings; %s",
		st.Nodes, st.Visited, st.Malicious, st.Review, st.Leads, st.DistinctFindingHashes,
		e.opt.Budget.Usage())})
}

func splitIdentity(k string) (name, email string) {
	i := strings.LastIndex(k, " <")
	if i < 0 || !strings.HasSuffix(k, ">") {
		return k, ""
	}
	return k[:i], k[i+2 : len(k)-1]
}

// Findings returns every recorded finding, strongest first.
func (e *Engine) Findings() []criteria.Finding {
	var out []criteria.Finding
	for _, n := range e.g.Nodes() {
		out = append(out, n.Findings...)
	}
	criteria.SortFindings(out)
	return out
}

// ReposByVerdict returns EXAMINED repositories matching a verdict, excluding
// corpora. A repository that was discovered but never cloned is reported
// separately -- see UnexaminedRepos -- because a verdict resting on one
// search-index hit is not the same claim as one resting on an examination.
func (e *Engine) ReposByVerdict(v criteria.Verdict) []graph.Node {
	var out []graph.Node
	for _, n := range e.g.Nodes() {
		if n.Kind == graph.KindRepo && !n.Corpus && n.Examined && n.Verdict == v {
			out = append(out, n)
		}
	}
	return out
}

// UnexaminedRepos are repositories the crawl found but never cloned, usually
// because a budget ran out.
func (e *Engine) UnexaminedRepos() []graph.Node {
	var out []graph.Node
	for _, n := range e.g.Nodes() {
		if n.Kind == graph.KindRepo && !n.Corpus && !n.Examined && len(n.Findings) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// CorpusRepos returns repositories that document the campaign rather than
// carrying it. Their findings are real matches and worth reading -- a
// third-party dossier is intelligence -- but they are not compromised.
func (e *Engine) CorpusRepos() []graph.Node {
	var out []graph.Node
	for _, n := range e.g.Nodes() {
		if n.Kind == graph.KindRepo && n.Corpus {
			out = append(out, n)
		}
	}
	return out
}

// AllRepoFindings returns every finding on every repository node.
func (e *Engine) AllRepoFindings() []criteria.Finding {
	var out []criteria.Finding
	for _, n := range e.g.Nodes() {
		if n.Kind == graph.KindRepo {
			out = append(out, n.Findings...)
		}
	}
	criteria.SortFindings(out)
	return out
}

// MaliciousRepos lists confirmed repositories with their provenance.
func (e *Engine) MaliciousRepos() []graph.Node {
	var out []graph.Node
	for _, n := range e.g.Nodes() {
		if n.Kind == graph.KindRepo && !n.Corpus && n.Examined && n.Verdict == criteria.VerdictMalicious {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
