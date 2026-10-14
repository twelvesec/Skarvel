package indicator

import (
	"regexp"
	"strconv"
	"strings"
)

// The miner is generous on purpose (see Extract), which floods the NEW IOCs and
// CANDIDATES lists with things that are not infrastructure: file names that end
// in a country code (install.sh, this.is), placeholder hosts, documentation
// addresses, version numbers read as IPs, identifiers read as secrets. isJunk
// is the filter between extraction and everything that follows. It only ever
// removes candidates; seeds and built-in indicators do not pass through it.

// ambiguousTLDs are real country codes that are also ordinary file extensions or
// English words, so `install.sh` and `this.is` look like hosts.
var ambiguousTLDs = map[string]bool{
	"sh": true, "pl": true, "is": true, "it": true, "in": true, "id": true,
	"no": true, "to": true, "at": true, "my": true, "im": true, "as": true,
	"ar": true, "be": true, "me": true, "cc": true,
}

// codeWords are the left-hand names that make `<word>.<ambiguous tld>` a file or
// a property rather than a host.
var codeWords = toSet("this", "that", "self", "data", "user", "item", "file", "name",
	"type", "index", "main", "setup", "install", "run", "start", "build", "test",
	"config", "script", "init", "app", "res", "req", "obj", "err", "event", "state",
	"props", "value", "key", "node", "result", "response", "request", "body", "list",
	"args", "params", "options", "opts", "ctx", "context", "window", "document",
	"element", "el", "target", "input", "output", "version", "url", "path", "dir",
	"cmd", "git", "npm", "yarn", "docker", "deploy", "update", "upgrade", "bootstrap",
	"boot", "entry", "server", "client", "db", "api", "env", "service", "task",
	"hook", "util", "utils", "helper", "helpers", "common", "base", "core", "lib",
	"module", "package", "release", "publish", "clean", "lint", "format", "check")

// placeholderHosts are the made-up names documentation and templates use.
var placeholderHosts = toSet("example.com", "example.org", "example.net", "example.edu",
	"test.com", "domain.com", "yourdomain.com", "mydomain.com", "your-domain.com",
	"yoursite.com", "mysite.com", "website.com", "site.com", "email.com",
	"company.com", "foo.com", "bar.com", "foobar.com", "acme.com", "host.com",
	"server.com", "localhost.com", "sample.com", "demo.com")

var placeholderTLDs = toSet("test", "invalid", "localhost", "local", "example", "internal", "lan", "home", "corp")

// commonHosts are large legitimate services. A host equal to one of these, or a
// subdomain of one, is never a campaign indicator -- promoting one would send
// the search across a large share of GitHub. Shared hosting that campaigns do
// abuse (github.io, vercel.app, pages.dev, workers.dev ...) is deliberately not
// listed.
var commonHosts = toSet("google.com", "googleusercontent.com", "googletagmanager.com",
	"google-analytics.com", "youtube.com", "youtu.be", "facebook.com", "fb.com",
	"twitter.com", "x.com", "linkedin.com", "instagram.com", "apple.com",
	"amazon.com", "amazonaws.com", "cloudfront.net", "azure.com", "azureedge.net",
	"windows.net", "microsoftonline.com", "live.com", "office.com", "bing.com",
	"wikipedia.org", "wikimedia.org", "medium.com", "reddit.com", "gitlab.com",
	"bitbucket.org", "sourceforge.net", "readthedocs.io", "mozilla.com",
	"jquery.com", "bootstrapcdn.com", "cdnjs.cloudflare.com", "fontawesome.com",
	"npmjs.com", "npmjs.org", "nodejs.org", "pypi.org", "rubygems.org",
	"maven.org", "crates.io", "golang.org", "go.dev", "docker.io", "docker.com",
	"github.com", "githubusercontent.com", "githubassets.com", "w3.org",
	"schema.org", "ietf.org", "openssl.org", "gnu.org", "apache.org", "eclipse.org",
	"creativecommons.org", "opensource.org", "stackoverflow.com", "stackexchange.com",
	"mit.edu", "visualstudio.com", "vscode.dev", "microsoft.com", "gravatar.com",
	"shields.io", "badgen.net", "img.shields.io", "codecov.io", "travis-ci.org",
	"circleci.com", "ssl.com", "letsencrypt.org", "digicert.com", "sentry.io")

func toSet(vs ...string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

// isCommonHost reports whether host is, or is a subdomain of, a large legitimate
// service or an entry of benignHosts.
func isCommonHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if benignHosts[h] {
		return true
	}
	for {
		if commonHosts[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// isJunk reports whether a mined candidate is noise rather than infrastructure.
func isJunk(v string, k Kind) bool {
	switch k {
	case KindDomain:
		return junkDomain(v)
	case KindURL:
		return junkURL(v)
	case KindIP:
		return junkIP(v)
	case KindSecret:
		return !secretLike(v)
	}
	return false
}

func junkDomain(d string) bool {
	h := strings.ToLower(strings.TrimSuffix(d, "."))
	if len(h) < 6 || placeholderHosts[h] || isCommonHost(h) {
		return true
	}
	i := strings.LastIndex(h, ".")
	if i < 0 {
		return true
	}
	left, tld := h[:i], h[i+1:]
	if placeholderTLDs[tld] {
		return true
	}
	if ambiguousTLDs[tld] {
		last := left
		if j := strings.LastIndex(left, "."); j >= 0 {
			last = left[j+1:]
		}
		if codeWords[last] || len(left) < 5 {
			return true
		}
	}
	return false
}

var (
	reTemplateChars = regexp.MustCompile("[{}<>$`\\\\|^\\s]|%[sdv]")
	reAssetURL      = regexp.MustCompile(`(?i)\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|otf|map|mp[34]|webm)(?:[?#].*)?$`)
)

func junkURL(u string) bool {
	if len(u) > 300 || reTemplateChars.MatchString(u) || reAssetURL.MatchString(u) {
		return true
	}
	host := hostOf(u)
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	if c := strings.LastIndex(host, ":"); c >= 0 && !strings.Contains(host, "]") {
		host = host[:c]
	}
	if host == "" {
		return true
	}
	if reIPOnly.MatchString(host) {
		return privateOrDocIP(host) || junkIP(host)
	}
	if !hasKnownTLD(host) {
		return true // localhost, an intranet name, a template variable
	}
	return junkDomain(host)
}

var reIPOnly = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

// reservedIPPrefixes are documentation, benchmarking, CGNAT and well-known
// resolver addresses.
var reservedIPPrefixes = []string{
	"192.0.0.", "192.0.2.", "198.51.100.", "203.0.113.", "198.18.", "198.19.",
	"1.2.3.4", "1.1.1.", "1.0.0.1", "8.8.4.4", "9.9.9.9", "208.67.222.222", "208.67.220.220",
}

func junkIP(ip string) bool {
	ip = strings.SplitN(ip, ":", 2)[0]
	if !validIP(ip) {
		return true
	}
	for _, p := range reservedIPPrefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	parts := strings.Split(ip, ".")
	first, _ := strconv.Atoi(parts[0])
	if first >= 224 { // multicast and reserved
		return true
	}
	if first == 100 {
		if second, _ := strconv.Atoi(parts[1]); second >= 64 && second <= 127 {
			return true // carrier-grade NAT
		}
	}
	// Every octet small: a version number (1.4.0.2), not an address.
	small := true
	for _, p := range parts {
		if n, _ := strconv.Atoi(p); n > 20 {
			small = false
		}
	}
	return small
}

// secretPrefixes are credential formats recognisable by their prefix; they skip
// the entropy and shape tests.
var secretPrefixes = []string{"ghp_", "gho_", "ghs_", "github_pat_", "glpat-", "sk-", "sk_live_",
	"xoxb-", "xoxp-", "xoxa-", "xoxs-", "AKIA", "ASIA", "AIza", "npm_", "pypi-"}

var (
	reHexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// secretLike decides whether a high-entropy token looks like a credential and
// not like an identifier, hash, UUID or alphabet table.
func secretLike(s string) bool {
	for _, p := range secretPrefixes {
		if strings.HasPrefix(s, p) && len(s) >= 20 {
			return true
		}
	}
	if len(s) < 20 || strings.ContainsAny(s, "()=&*%^ ") {
		return false
	}
	if reHexOnly.MatchString(s) || reUUID.MatchString(s) {
		return false // digests and ids, not secrets
	}
	var lower, upper, digits int
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower++
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	// Identifiers (processDataFromServer, my_long_function_name) have no digits;
	// a random token has several, and all three classes.
	if lower == 0 || upper == 0 || digits < 2 {
		return false
	}
	if hasSequentialRun(s, 6) {
		return false // an alphabet table such as ABCDEFGHIJKLMNOP...
	}
	return Entropy(s) >= 4.2
}

// hasSequentialRun reports whether s contains n consecutive characters in
// ascending order (abcdef, 123456).
func hasSequentialRun(s string, n int) bool {
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}
