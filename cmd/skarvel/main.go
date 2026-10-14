// Command skarvel hunts public GitHub or Bitbucket repositories for a campaign
// indicator and everything that indicator leads to.
//
// The whole pipeline -- code search across every encoding of the IOC, cloning,
// content signatures, forged-timestamp analysis, author correlation, indicator
// mining and maliciousness scoring -- runs automatically. The analyst supplies
// the IOC and, optionally, the platform.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"skarvel/internal/bbapi"
	"skarvel/internal/crawl"
	"skarvel/internal/criteria"
	"skarvel/internal/event"
	"skarvel/internal/ghapi"
)

const usage = `skarvel — hunt public repositories for a campaign IOC

USAGE
  skarvel --ioc <IOC> [--platform github|bitbucket] [-a] [--plain]
  skarvel --repo <owner/name|URL> [--ioc <IOC>] [--platform github|bitbucket]

FLAGS
  --ioc <IOC>          indicator to hunt: a domain, IP, URL, secret or any
                       string, raw or encoded (base64/hex are decoded and
                       hunted in both forms)
  -r, --repo <repo>    scan this one repository (owner/name or its URL) instead
                       of hunting: every branch and pull request is cloned and
                       examined, nothing else is searched or followed. --ioc is
                       optional here and adds indicators to match inside it. The
                       platform is taken from a URL, else --platform.
  --platform <name>    github (default) or bitbucket
  --workspace <slug>   Bitbucket only, optional, repeatable: extra workspaces to
                       search in addition to the built-in campaign workspaces
                       (Bitbucket has no global code search)
  -a, --activity       show the live activity feed in the dashboard
  --plain              no full-screen dashboard and no colours: a one-line
                       progress indicator and the plain-text report
  --version            print the version

ENVIRONMENT
  NO_COLOR             if set, disables colours (the dashboard stays)
  GITHUB_TOKEN         required for GitHub; a token with NO scopes is enough
  BITBUCKET_TOKEN      optional (or BITBUCKET_USER + BITBUCKET_APP_PASSWORD);
                       raises Bitbucket's anonymous rate limit

OUTPUT
  On a terminal, a live dashboard runs on stderr during the hunt and the report
  is printed in colour. Results also go to
  skarvel_output_<YYYYMMDD>_<HHMMSS>.txt in the current directory (always plain
  text). Every finding requires manual verification.
`

// builtinWorkspaces are Bitbucket workspaces confirmed to have hosted the
// campaign. Bitbucket search is workspace-scoped, so without these a Bitbucket
// hunt would have nowhere to look.
const version = "v0.15"

var builtinWorkspaces = []string{"bloxbits"}

// Internal defaults. These were flags of the old "expand" command; they are
// budgets and policies, not things an analyst should have to choose.
const (
	maxRepos    = 300
	maxAPICalls = 20000
	maxSearches = 500
	maxDepth    = 6
	maxDuration = 4 * time.Hour
	maxRepoMB   = 2048
	maxDiskGiB  = 20
)

type config struct {
	iocs        []string
	platform    string
	platformSet bool
	workspaces  []string
	repo        string // single-repository mode: "owner/name"
	plain       bool
	activity    bool
}

func parseArgs(args []string) (*config, error) {
	c := &config{platform: criteria.HostGitHub}
	var repoHost string // platform implied by a --repo URL
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		value := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		var v string
		var err error
		switch name {
		case "-h", "--help", "-help":
			return nil, errHelp
		case "--version", "-version":
			return nil, errVersion
		case "-a", "--activity", "-activity":
			if hasVal {
				return nil, fmt.Errorf("%s takes no value", name)
			}
			c.activity = true
		case "--plain", "-plain":
			if hasVal {
				return nil, fmt.Errorf("%s takes no value", name)
			}
			c.plain = true
		case "--ioc", "-ioc":
			if v, err = value(); err != nil {
				return nil, err
			}
			if v = strings.TrimSpace(v); v == "" {
				return nil, errors.New("--ioc must not be empty")
			}
			c.iocs = append(c.iocs, v)
		case "--repo", "-repo", "-r":
			if v, err = value(); err != nil {
				return nil, err
			}
			if c.repo != "" {
				return nil, errors.New("--repo can be given only once")
			}
			if c.repo, repoHost, err = parseRepo(v); err != nil {
				return nil, err
			}
		case "--platform", "-platform":
			if v, err = value(); err != nil {
				return nil, err
			}
			c.platformSet = true
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "github", "gh":
				c.platform = criteria.HostGitHub
			case "bitbucket", "bb":
				c.platform = criteria.HostBitbucket
			default:
				return nil, fmt.Errorf("--platform must be github or bitbucket, got %q", v)
			}
		case "--workspace", "-workspace":
			if v, err = value(); err != nil {
				return nil, err
			}
			c.workspaces = append(c.workspaces, v)
		default:
			return nil, fmt.Errorf("unknown argument %q", args[i])
		}
	}
	if c.repo == "" && len(c.iocs) == 0 {
		return nil, errors.New("--ioc or --repo is required")
	}
	if repoHost != "" {
		if c.platformSet && c.platform != repoHost {
			return nil, fmt.Errorf("--repo URL is on %s but --platform is %s", repoHost, c.platform)
		}
		c.platform = repoHost
	}
	if c.repo != "" {
		if len(c.workspaces) > 0 {
			return nil, errors.New("--workspace cannot be combined with --repo")
		}
		if c.platform == criteria.HostBitbucket {
			c.workspaces = []string{strings.SplitN(c.repo, "/", 2)[0]}
		}
		return c, nil
	}
	if len(c.workspaces) > 0 && c.platform != criteria.HostBitbucket {
		return nil, errors.New("--workspace only applies with --platform bitbucket")
	}
	if c.platform == criteria.HostBitbucket {
		c.workspaces = append(append([]string(nil), builtinWorkspaces...), c.workspaces...)
	}
	return c, nil
}

// parseRepo accepts "owner/name" or a repository URL on github.com or
// bitbucket.org, and returns the "owner/name" plus the host the URL implies
// ("" for the bare form).
func parseRepo(v string) (repo, host string, err error) {
	v = strings.TrimSpace(v)
	rest := v
	if strings.Contains(v, "://") {
		u, perr := url.Parse(v)
		if perr != nil || u.Host == "" {
			return "", "", fmt.Errorf("--repo: cannot parse %q", v)
		}
		switch strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.") {
		case "github.com":
			host = criteria.HostGitHub
		case "bitbucket.org":
			host = criteria.HostBitbucket
		default:
			return "", "", fmt.Errorf("--repo: %q is not a github.com or bitbucket.org URL", v)
		}
		rest = u.Path
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("--repo must be owner/name or a repository URL, got %q", v)
	}
	if host == "" && len(parts) != 2 {
		return "", "", fmt.Errorf("--repo must be owner/name or a repository URL, got %q", v)
	}
	name := strings.TrimSuffix(parts[1], ".git")
	for _, p := range []string{parts[0], name} {
		if strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != "" || p == "." || p == ".." {
			return "", "", fmt.Errorf("--repo: %q has characters not valid in a repository path", v)
		}
	}
	return parts[0] + "/" + name, host, nil
}

var (
	errHelp    = errors.New("help requested")
	errVersion = errors.New("version requested")
)

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if errors.Is(err, errHelp) {
		fmt.Print(usage)
		return
	}
	if errors.Is(err, errVersion) {
		fmt.Println("skarvel", version)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, usage)
		os.Exit(2)
	}
	os.Exit(run(cfg))
}

func run(cfg *config) int {
	started := time.Now()

	client, err := newPlatform(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// Clones live in a private temporary directory that is removed on exit;
	// each clone is already deleted as soon as its repository is analysed.
	cache, err := os.MkdirTemp("", "skarvel-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer os.RemoveAll(cache)

	// The wall-clock budget is enforced between visits by the engine; the
	// context deadline enforces it inside one.
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration+30*time.Second)
	defer cancel()
	// The dashboard takes the whole of stderr when it is a terminal; --plain
	// (or a dumb terminal) keeps the old single status line, and anything
	// that is not a terminal gets no live output at all.
	mode := modeSilent
	if isTTY(os.Stderr) {
		mode = modeLine
		if !cfg.plain && os.Getenv("TERM") != "dumb" && enableVT(os.Stderr) {
			mode = modeFull
		}
	}
	dash := newDash(palette{on: !cfg.plain && colorWanted(os.Stderr)}, mode, cfg.iocs, cfg.platform, started)
	dash.target = cfg.repo
	dash.out = os.Stderr
	dash.showActivity = cfg.activity
	dash.size = func() (int, int) { return termSize(os.Stderr) }

	interrupted := make(chan struct{})
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		close(interrupted)
		if mode == modeFull {
			dash.notify("interrupted · writing results so far · ctrl-c again to abort")
		} else {
			dash.leave()
			fmt.Fprintln(os.Stderr, "\n[*] interrupted — writing results so far (press Ctrl-C again to abort)")
		}
		cancel()
		<-sig
		dash.leave()
		os.RemoveAll(cache)
		os.Exit(130)
	}()

	bus := event.NewBus()
	if bc, ok := client.(*bbapi.Client); ok {
		bc.Logf = bus.Logf
	}
	budget := &crawl.Budget{
		MaxAPICalls: maxAPICalls, MaxSearches: maxSearches, MaxRepos: maxRepos,
		MaxDiskBytes: maxDiskGiB << 30, MaxDepth: maxDepth, MaxDuration: maxDuration,
	}
	analyzer := crawl.NewGitAnalyzer(cache, bus, budget)
	analyzer.Platform = cfg.platform
	engine := crawl.NewEngine(client, analyzer, bus, crawl.Options{
		Indicators: cfg.iocs,
		TargetRepo: cfg.repo,
		Budget:     budget,
		MaxRepoKB:  maxRepoMB * 1024,
		Platform:   cfg.platform,
		// Both are on by default: mined C2 locators are only ever taken from
		// files already rated definitive, and anything reached through an
		// identity lead stays labelled and is reported for manual verification.
		AutoPromote: true,
		FollowLeads: true,
	})

	events := bus.Subscribe(8192)
	progressDone := make(chan struct{})
	go func() {
		dash.loop(events)
		close(progressDone)
	}()

	runErr := engine.Run(ctx)
	bus.Close()
	<-progressDone

	stop := budget.StopReason()
	select {
	case <-interrupted:
		stop = "interrupted"
	default:
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			stop = runErr.Error()
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) && stop == "" {
			stop = "time budget exhausted"
		}
	}

	var warnings []string
	if stop != "" {
		warnings = append(warnings, fmt.Sprintf("Hunt stopped early (%s); results may be incomplete.", stop))
	}
	if failed, unverified, last := engine.SearchProblems(); failed > 0 || unverified > 0 {
		w := fmt.Sprintf("%d search(es) failed", failed)
		if unverified > 0 {
			w += fmt.Sprintf(", %d returned unverifiable zero results", unverified)
		}
		w += "; results are INCOMPLETE and absence of findings proves nothing."
		if last != "" {
			w += " Last error: " + firstLine(last, 200)
		}
		warnings = append(warnings, w)
	}

	res := classify(engine.Graph().Nodes(), cfg.platform)
	res.setIndicators(engine.NewIndicators())
	s := summary{
		IOCs: cfg.iocs, Repo: cfg.repo, Platform: cfg.platform, Elapsed: time.Since(started),
		Examined: dash.examined, Discovered: dash.discovered, Hits: dash.hits, Promoted: dash.promoted,
	}
	text := render(res, warnings, s)
	path, werr := writeOutput(started, text)
	if out := (palette{on: !cfg.plain && colorWanted(os.Stdout)}); out.on {
		w, _ := termSize(os.Stdout)
		fmt.Print(renderPretty(out, res, warnings, s, w))
	} else {
		fmt.Print(text)
	}
	if werr != nil {
		fmt.Fprintf(os.Stderr, "error: could not write output file: %v\n", werr)
		return 1
	}
	errP := palette{on: !cfg.plain && colorWanted(os.Stderr)}
	fmt.Fprintf(os.Stderr, "%s results written to %s\n", errP.s(stCyan, "[*]"), errP.s(stBold, path))
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return 1
	}
	return 0
}

// newPlatform builds the API client for the selected platform, or explains
// which credential or workspace is missing.
func newPlatform(cfg *config) (crawl.Platform, error) {
	if cfg.platform != criteria.HostBitbucket {
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		if token == "" {
			token = strings.TrimSpace(os.Getenv("GH_TOKEN"))
		}
		if token == "" && cfg.repo != "" {
			// Reading one public repository needs no search, so no token: the
			// anonymous API limit is ample for the few calls this makes.
			fmt.Fprintln(os.Stderr, "[*] GITHUB_TOKEN not set; scanning anonymously (set it to avoid API rate limits)")
			return ghapi.New(""), nil
		}
		if token == "" {
			return nil, errors.New("GITHUB_TOKEN is not set\n\n" +
				"GitHub code search requires authentication. Create a token with NO scopes at\n" +
				"  https://github.com/settings/tokens\n" +
				"then run:  export GITHUB_TOKEN=ghp_...")
		}
		c := ghapi.New(token)
		actx, acancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer acancel()
		if err := c.CheckAuth(actx); err != nil {
			return nil, fmt.Errorf("GitHub rejected the token (%v)\n\n"+
				"Check that GITHUB_TOKEN is current and copied completely; create a new one\n"+
				"with NO scopes at https://github.com/settings/tokens", err)
		}
		return c, nil
	}

	auth := bbapi.AuthFromEnv(os.Getenv)
	if bbapi.IsAccountAPIToken(auth.Token) {
		return nil, errors.New(accountTokenHelp(auth))
	}
	c := bbapi.New(cfg.workspaces, auth)

	// Fail before the crawl, not seven searches into it: a slug that does not
	// exist must never be reported as a clean sweep.
	pctx, pcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer pcancel()
	var usable int
	for _, st := range c.CheckWorkspaces(pctx) {
		switch {
		case st.Unauthorized:
			// Every search would fail with the same 401, and a hunt whose
			// searches all fail reads like a clean sweep. Stop here instead.
			reason := ""
			if _, msg, ok := strings.Cut(st.Err, "Bitbucket says: "); ok {
				reason = "Bitbucket says: " + msg + "\n\n"
			}
			return nil, errors.New("Bitbucket rejected the credentials (401 unauthorized)\n\n" + reason +
				"Public workspaces need no credentials: unset BITBUCKET_TOKEN, BITBUCKET_USER\n" +
				"and BITBUCKET_APP_PASSWORD to hunt anonymously. Otherwise:\n" +
				"  - The password you sign in to bitbucket.org with does NOT work for the API.\n" +
				"  - Use an API token *with scopes*: at\n" +
				"    https://id.atlassian.com/manage-profile/security/api-tokens choose\n" +
				"    \"Create API token with scopes\", app Bitbucket, read scopes for\n" +
				"    repositories and workspaces. Then:\n" +
				"      BITBUCKET_USER=<Atlassian account email>  BITBUCKET_APP_PASSWORD=<token>\n" +
				"    (the email, not the Bitbucket username; a token without scopes is refused)\n" +
				"  - BITBUCKET_TOKEN alone is for workspace or repository access tokens.")
		case !st.Exists:
			fmt.Fprintf(os.Stderr, "[*] warning: no such Bitbucket workspace %q, skipped\n", st.Slug)
		case st.Err != "":
			fmt.Fprintf(os.Stderr, "[*] warning: Bitbucket workspace %q: %s\n", st.Slug, st.Err)
			usable++
		default:
			usable++
		}
	}
	if usable == 0 {
		return nil, fmt.Errorf("none of the Bitbucket workspaces exist (%s); "+
			"a workspace slug is the first path segment of a bitbucket.org URL",
			strings.Join(c.Workspaces(), ", "))
	}
	return c, nil
}

// accountTokenHelp explains why an Atlassian account API token in
// BITBUCKET_TOKEN could not be used, naming the variable that is actually in
// the way (never printing a value).
func accountTokenHelp(a bbapi.Auth) string {
	var why string
	switch {
	case a.User == "":
		why = "BITBUCKET_USER is not set in this environment. Bitbucket accepts this kind of\n" +
			"token only together with your Atlassian account email (HTTP Basic auth):\n" +
			"  export BITBUCKET_USER=you@example.com"
	default:
		why = "BITBUCKET_APP_PASSWORD is also set (perhaps left over from an earlier attempt),\n" +
			"so it is unclear which password belongs to BITBUCKET_USER. Remove it:\n" +
			"  unset BITBUCKET_APP_PASSWORD"
	}
	return "BITBUCKET_TOKEN holds an Atlassian account API token (ATATT…), but " + why + "\n\n" +
		"Alternatively put the token in the user/password pair:\n" +
		"  unset BITBUCKET_TOKEN\n" +
		"  export BITBUCKET_USER=you@example.com BITBUCKET_APP_PASSWORD=ATATT…\n" +
		"To see which Bitbucket variables are set (names only):\n" +
		"  env | grep -o '^BITBUCKET_[A-Z_]*'"
}

func firstLine(s string, n int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
