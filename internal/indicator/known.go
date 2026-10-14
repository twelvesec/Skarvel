package indicator

// Known is the built-in indicator set: campaign infrastructure already
// confirmed by investigation, seeded on every crawl without being asked for.
//
// These are Confirmed, so a match is Tier A. Adding one here means every future
// hunt searches for it automatically, which is the point -- the operator reuses
// infrastructure across lures, and an analyst should not have to remember to
// type each domain.
//
// The bar for entry is confirmation in a case file, not suspicion. Anything
// less belongs in the review queue.
var Known = []Indicator{
	{Value: "ipregionchecker.org", Kind: KindDomain, Source: "case01 §2", Confirmed: true},
	{Value: "isillegalregion.com", Kind: KindDomain, Source: "case01 §12", Confirmed: true},

	// The lure kit. Both serve the same path grammar --
	// /settings/{linux,mac,windows}?flag=N -- which is what identifies them as
	// one kit on two domains rather than two unrelated hosts.
	{Value: "codeprettier.pro", Kind: KindDomain, Source: "case01 §12", Confirmed: true},
	{Value: "code-beautify.com", Kind: KindDomain, Source: "case03 expansion, 2026-08-08", Confirmed: true},

	// Stage-2 collection tier. Raw IP over plain HTTP; survives takedown of the
	// disposable lure domains above.
	{Value: "172.86.126.227", Kind: KindIP, Source: "case01 §13.6", Confirmed: true},

	// Path prefix rather than a full URL: the trailing token is per-instance
	// operator enumeration (3aeb34a31..39), so matching one literal misses the
	// rest of the family.
	{Value: "/api/ip-check-encrypted/", Kind: KindGeneric, Source: "case01 §12.4", Confirmed: true},

	// Hardcoded secret shared across the family's payloads.
	{Value: "SuperStr0ngSecret@)@^", Kind: KindSecret, Source: "case01 §13", Confirmed: true},
}

// KnownValues returns the built-in indicator strings.
func KnownValues() []string {
	out := make([]string, 0, len(Known))
	for _, in := range Known {
		out = append(out, in.Value)
	}
	return out
}
