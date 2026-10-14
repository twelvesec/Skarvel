package crawl

import (
	"context"
	"errors"
	"testing"

	"skarvel/internal/event"
	"skarvel/internal/ghapi"
)

// failingGH rejects every search, as GitHub does for a revoked token.
type failingGH struct{ fakeGH }

func (f *failingGH) SearchCode(context.Context, string, int) ([]ghapi.CodeHit, int, error) {
	return nil, 0, errors.New("401 unauthorized: GITHUB_TOKEN is missing, expired, or malformed")
}

// A crawl whose searches all fail finds nothing. That must be reported as a
// failure, never left to read as a clean sweep.
func TestFailedSearchesAreReported(t *testing.T) {
	bus := event.NewBus()
	drain := collect(bus)
	e := NewEngine(&failingGH{}, &fakeAnalyzer{}, bus, Options{
		Indicators: []string{"evil.example.org"}, Budget: DefaultBudget(),
	})
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	drain()

	failed, _, last := e.SearchProblems()
	// canary + the seed + every built-in indicator
	if failed < 2 || last == "" {
		t.Fatalf("SearchProblems = %d, %q; want every failed search counted", failed, last)
	}
	if len(e.MaliciousRepos()) != 0 {
		t.Fatal("no search succeeded, yet repositories were reported")
	}
}
