package ghapi

import (
	"net/http"
	"testing"
	"time"
)

func resp(status int, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// The secondary rate limit is the one that actually stops long runs, and it
// arrives with no useful headers at all -- only a message in the body.
func TestSecondaryRateLimitIsRecognisedFromBodyAlone(t *testing.T) {
	body := `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again.","documentation_url":"https://docs.github.com/..."}`

	wait, ok := rateLimitWait(resp(403, nil), body, 0)
	if !ok {
		t.Fatal("secondary rate limit must be treated as retryable; returning false aborts the run")
	}
	if wait < time.Minute {
		t.Errorf("wait = %s, want at least 60s per GitHub guidance", wait)
	}
}

func TestSecondaryRateLimitBacksOff(t *testing.T) {
	body := `{"message":"You have exceeded a secondary rate limit."}`

	first, _ := rateLimitWait(resp(403, nil), body, 0)
	second, _ := rateLimitWait(resp(403, nil), body, 1)
	if second <= first {
		t.Errorf("repeat hits must wait longer: attempt0=%s attempt1=%s", first, second)
	}

	capped, _ := rateLimitWait(resp(403, nil), body, 10)
	if capped > 5*time.Minute {
		t.Errorf("backoff must stay capped, got %s", capped)
	}
}

func TestRetryAfterHeaderWins(t *testing.T) {
	wait, ok := rateLimitWait(resp(429, map[string]string{"retry-after": "30"}), "", 0)
	if !ok {
		t.Fatal("retry-after must be honoured")
	}
	if wait < 30*time.Second || wait > 32*time.Second {
		t.Errorf("wait = %s, want ~30s", wait)
	}
}

func TestPrimaryLimitUsesResetTimestamp(t *testing.T) {
	reset := time.Now().Add(90 * time.Second).Unix()
	wait, ok := rateLimitWait(resp(403, map[string]string{
		"x-ratelimit-remaining": "0",
		"x-ratelimit-reset":     itoa(reset),
	}), "", 0)
	if !ok {
		t.Fatal("exhausted primary quota must be retryable")
	}
	if wait < 80*time.Second || wait > 100*time.Second {
		t.Errorf("wait = %s, want ~90s", wait)
	}
}

// A 403 that is genuinely a refusal must fail fast rather than sleeping.
func TestPlainForbiddenIsNotRetried(t *testing.T) {
	body := `{"message":"Resource not accessible by personal access token"}`
	if _, ok := rateLimitWait(resp(403, nil), body, 0); ok {
		t.Error("a permission error must not be mistaken for throttling")
	}
}

func TestIsSecondaryLimit(t *testing.T) {
	yes := []string{
		"You have exceeded a secondary rate limit.",
		"You have triggered an abuse detection mechanism.",
		"Please wait a few minutes before you try again.",
	}
	no := []string{
		"Not Found",
		"Bad credentials",
		"Resource not accessible by personal access token",
		"",
	}
	for _, s := range yes {
		if !isSecondaryLimit(s) {
			t.Errorf("should detect throttling: %q", s)
		}
	}
	for _, s := range no {
		if isSecondaryLimit(s) {
			t.Errorf("should not detect throttling: %q", s)
		}
	}
}

func itoa(n int64) string {
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
