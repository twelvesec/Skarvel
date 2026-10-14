package criteria

import "testing"

func TestForgedPersonas(t *testing.T) {
	var s []ClockSample
	add := func(name string, n int, onHour bool) {
		for i := 0; i < n; i++ {
			c := ClockSample{Hour: 12, Valid: true, AuthorName: name, AuthorEmail: name + "@x"}
			if !onHour {
				c.Min, c.Sec = 17, i+1
			}
			s = append(s, c)
		}
	}
	add("persona", 5, true)
	add("organic", 40, false)
	add("tiny", 2, true)            // below PersonaMinCommits
	add("dependabot[bot]", 9, true) // automation is excluded

	got := ForgedPersonas(s)
	if len(got) != 1 || got[0].Name != "persona" || got[0].Commits != 5 || got[0].Hour != 12 {
		t.Fatalf("ForgedPersonas = %+v", got)
	}
	f := got[0].ToFinding("o/r")
	if f.Tier != TierC || f.Tier.Expands() {
		t.Errorf("persona finding must be supporting and non-expanding, got tier %s", f.Tier)
	}
	if a := Assess([]Finding{f}); a.Verdict != VerdictClean || a.Expand {
		t.Errorf("a persona alone must not convict a repository: %+v", a)
	}
}
