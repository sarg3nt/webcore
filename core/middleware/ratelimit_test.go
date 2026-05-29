package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimiterAllowsBurstThenBlocks(t *testing.T) {
	// 1 rps, burst 2: first two requests pass, third is throttled.
	h := RateLimiter(1, 2, time.Minute)(okHandler())

	codes := make([]int, 3)
	for i := range codes {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.7:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		codes[i] = w.Code
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Errorf("first two should pass, got %v", codes)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("third should be 429, got %d", codes[2])
	}
}

func TestRateLimiterIsPerIP(t *testing.T) {
	h := RateLimiter(1, 1, time.Minute)(okHandler())

	send := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if got := send("198.51.100.1:1"); got != http.StatusOK {
		t.Fatalf("IP A first = %d, want 200", got)
	}
	// Different IP gets its own bucket — still allowed.
	if got := send("198.51.100.2:1"); got != http.StatusOK {
		t.Errorf("IP B first = %d, want 200", got)
	}
	// IP A is now out of budget.
	if got := send("198.51.100.1:1"); got != http.StatusTooManyRequests {
		t.Errorf("IP A second = %d, want 429", got)
	}
}

func TestRateLimiterSets429RetryAfter(t *testing.T) {
	h := RateLimiter(1, 1, time.Minute)(okHandler())
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.0.2.9:9"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	send() // consume burst
	w := send()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 response should set Retry-After")
	}
}

func TestRateLimiterMalformedRemoteAddr(t *testing.T) {
	// No port — SplitHostPort fails, falls back to the raw RemoteAddr.
	h := RateLimiter(1, 1, time.Minute)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "no-port-here"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("first request should pass regardless of addr shape, got %d", w.Code)
	}
}
