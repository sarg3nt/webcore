// Package middleware provides reusable net/http middleware for webcore apps:
// per-IP rate limiting and security-header / CSP injection.
package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxRateLimitBuckets caps the per-IP bucket map between prune ticks so a
// client cycling source addresses (trivial from an IPv6 /64) cannot grow it
// without bound within a single ttl window. When the cap is hit, an arbitrary
// existing bucket is evicted to make room — a slight fairness cost under
// active attack, bounded memory always. Variable (not const) so tests can
// lower it.
var maxRateLimitBuckets = 65536

// RateLimiter returns a middleware that token-bucket throttles each source IP
// at rps requests per second with a burst of burst. Source IP is taken from
// r.RemoteAddr directly (TCP-level), avoiding header-spoof risks. Stale
// per-IP buckets are pruned every ttl, and the map is hard-capped at
// maxRateLimitBuckets between prunes.
//
// A single background goroutine prunes stale buckets for the lifetime of the
// process; create one RateLimiter at startup rather than per-request (each
// construction starts a goroutine that is never stopped).
func RateLimiter(rps float64, burst int, ttl time.Duration) func(http.Handler) http.Handler {
	type slot struct {
		lim  *rate.Limiter
		last time.Time
	}
	var (
		mu      sync.Mutex
		buckets = map[string]*slot{}
	)
	go func() {
		t := time.NewTicker(ttl)
		defer t.Stop()
		for range t.C {
			cutoff := time.Now().Add(-ttl)
			mu.Lock()
			for k, s := range buckets {
				if s.last.Before(cutoff) {
					delete(buckets, k)
				}
			}
			mu.Unlock()
		}
	}()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			mu.Lock()
			s, ok := buckets[ip]
			if !ok {
				if len(buckets) >= maxRateLimitBuckets {
					// Evict an arbitrary entry (map iteration order is
					// randomized) to keep memory bounded under source-IP
					// cycling.
					for k := range buckets {
						delete(buckets, k)
						break
					}
				}
				s = &slot{lim: rate.NewLimiter(rate.Limit(rps), burst)}
				buckets[ip] = s
			}
			s.last = time.Now()
			allowed := s.lim.Allow()
			mu.Unlock()
			if !allowed {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
