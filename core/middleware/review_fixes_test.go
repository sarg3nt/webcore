package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSourcelessCSPDirectivesKept: upgrade-insecure-requests and
// block-all-mixed-content are valid, security-strengthening directives with no
// source list — the sanitizer must not drop them.
func TestSourcelessCSPDirectivesKept(t *testing.T) {
	w := serve(Config{
		LocalAssets:  true,
		ExtraSources: []string{"upgrade-insecure-requests", "block-all-mixed-content"},
	}, false)
	csp := w.Header().Get("Content-Security-Policy")
	for _, d := range []string{"upgrade-insecure-requests", "block-all-mixed-content"} {
		if !strings.Contains(csp, d) {
			t.Errorf("sourceless directive %q dropped from CSP: %q", d, csp)
		}
	}
	// Injection guard still holds on the relaxed regex.
	w2 := serve(Config{LocalAssets: true, ExtraSources: []string{"img-src x; script-src 'unsafe-eval'"}}, false)
	if strings.Contains(w2.Header().Get("Content-Security-Policy"), "unsafe-eval") {
		t.Error("';' injection must still be rejected")
	}
}

// TestRateLimiterBucketCap: cycling source IPs must not grow the bucket map
// without bound within a prune window.
func TestRateLimiterBucketCap(t *testing.T) {
	old := maxRateLimitBuckets
	maxRateLimitBuckets = 8
	defer func() { maxRateLimitBuckets = old }()

	h := RateLimiter(100, 100, time.Hour)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 100 distinct IPs against a cap of 8: every request must still be served
	// (eviction, not rejection) and nothing panics or leaks unbounded.
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1", i%250+1)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 (cap must evict, not reject)", i, w.Code)
		}
	}
}
