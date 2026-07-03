package middleware

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Config configures the SecurityHeaders middleware. The zero value is usable:
// it emits the CDN-allowing CSP and the default referrer / permissions / HSTS
// headers. Apps that read settings from the environment populate this struct
// themselves — this package never reads os.Getenv, keeping the security policy
// explicit and testable.
type Config struct {
	// LocalAssets selects the strict same-origin CSP (true) over the
	// CDN-allowing CSP (false). Ignored when Directives is set.
	LocalAssets bool

	// Directives, when non-nil, is the exact list of CSP directive lines to
	// use, overriding the built-in local/CDN sets. ExtraSources and ReportURI
	// are still appended. Use this during cutover to preserve an app's precise
	// existing CSP.
	Directives []string

	// ExtraSources are additional CSP directive lines. Each is sanitized
	// before inclusion; entries that look like header-injection attempts
	// (embedded ';', CRLF, control/non-ASCII bytes, or not shaped like a
	// "directive source [source...]" line) are silently dropped.
	ExtraSources []string

	// ReportURI, when a valid absolute http(s) URL, adds a report-uri
	// directive. Relative paths, non-http(s) schemes, and values with embedded
	// whitespace/newlines are dropped.
	ReportURI string

	// ReferrerPolicy overrides the default "strict-origin-when-cross-origin".
	ReferrerPolicy string

	// PermissionsPolicy overrides the default sensor-disabling policy.
	PermissionsPolicy string

	// HSTS overrides the default "max-age=31536000; includeSubDomains".
	HSTS string

	// HSTSOnlyOverTLS emits the Strict-Transport-Security header only on TLS
	// connections. Handy in dev where the same server also answers plain HTTP
	// and you don't want browsers pinning HSTS off a localhost request.
	HSTSOnlyOverTLS bool
}

const (
	defaultReferrerPolicy    = "strict-origin-when-cross-origin"
	defaultHSTS              = "max-age=31536000; includeSubDomains"
	defaultPermissionsPolicy = "geolocation=(), microphone=(), camera=(), usb=(), payment=(), interest-cohort=(), browsing-topics=()"
)

// defaultLocalDirectives is the strict, same-origin-only CSP used when assets
// are served from the embedded FS. 'unsafe-inline' stays on script/style
// because the Tailwind Play CDN runtime injects <style> tags and base layouts
// ship an inline tailwind.config script; a fully strict policy needs
// precompiled Tailwind CSS.
var defaultLocalDirectives = []string{
	"default-src 'self'",
	"script-src 'self' 'unsafe-inline'",
	"style-src 'self' 'unsafe-inline'",
	"img-src 'self' data: blob:",
	"font-src 'self' data:",
	"connect-src 'self' ws: wss:",
	"frame-ancestors 'none'",
	"base-uri 'self'",
	"form-action 'self'",
}

// defaultCDNDirectives allows the CDN origins both apps load Tailwind / htmx /
// charting libs from. connect-src deliberately stays restricted to 'self' (+
// websockets) even though script/style trust the CDNs: defense-in-depth so a
// compromised CDN script can run but cannot exfiltrate via fetch/XHR/SSE.
var defaultCDNDirectives = []string{
	"default-src 'self'",
	"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net",
	"style-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net",
	"img-src 'self' data: blob: https://cdn.jsdelivr.net",
	"font-src 'self' data:",
	"connect-src 'self' ws: wss:",
	"frame-ancestors 'none'",
	"base-uri 'self'",
	"form-action 'self'",
}

// validCSPDirective matches a single CSP directive line: a directive name
// followed by zero or more source expressions, with no semicolons (which would
// close the directive and let an injected value splice in new directives).
// `+` and `=` are allowed so base64 nonce-/sha256- expressions aren't dropped.
// The source group is optional because valid CSP includes sourceless
// directives like `upgrade-insecure-requests` and `block-all-mixed-content`.
var validCSPDirective = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]+(\s+[a-zA-Z0-9'_:/.\-*+=]+)*$`)

// cspContainsForbidden reports whether s contains any byte with no business in
// a CSP header value: ASCII control chars (< 0x20, 0x7F) or any non-ASCII rune.
// Guards against header smuggling via configured CSP values.
func cspContainsForbidden(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return true
		}
	}
	return false
}

// sanitizeCSPExtraSource validates a single extra CSP directive line, returning
// the trimmed value and an ok flag. Rejects ';', forbidden bytes, and anything
// not shaped like a valid "directive source [source...]" line.
func sanitizeCSPExtraSource(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", false
	}
	if strings.ContainsAny(trimmed, ";") || cspContainsForbidden(trimmed) {
		return "", false
	}
	if !validCSPDirective.MatchString(trimmed) {
		return "", false
	}
	return trimmed, true
}

// sanitizeCSPReportURI validates a report-uri value. Accepts an absolute
// http(s) URL; rejects relative paths, non-http(s) schemes, and values with
// embedded whitespace or newlines.
func sanitizeCSPReportURI(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", false
	}
	if strings.ContainsAny(trimmed, " ;") || cspContainsForbidden(trimmed) {
		return "", false
	}
	u, err := url.Parse(trimmed)
	if err != nil || u == nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	return trimmed, true
}

// buildCSP assembles the Content-Security-Policy value from cfg.
func (cfg Config) buildCSP() string {
	var directives []string
	switch {
	case cfg.Directives != nil:
		directives = append(directives, cfg.Directives...)
	case cfg.LocalAssets:
		directives = append(directives, defaultLocalDirectives...)
	default:
		directives = append(directives, defaultCDNDirectives...)
	}

	for _, source := range cfg.ExtraSources {
		if clean, ok := sanitizeCSPExtraSource(source); ok {
			directives = append(directives, clean)
		}
	}
	if uri, ok := sanitizeCSPReportURI(cfg.ReportURI); ok {
		directives = append(directives, "report-uri "+uri)
	}
	return strings.Join(directives, "; ")
}

// SecurityHeaders returns a middleware that sets Content-Security-Policy,
// X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy,
// X-XSS-Protection, and (subject to HSTSOnlyOverTLS) Strict-Transport-Security
// on every response.
func SecurityHeaders(cfg Config) func(http.Handler) http.Handler {
	csp := cfg.buildCSP()

	referrer := cfg.ReferrerPolicy
	if referrer == "" {
		referrer = defaultReferrerPolicy
	}
	permissions := cfg.PermissionsPolicy
	if permissions == "" {
		permissions = defaultPermissionsPolicy
	}
	hsts := cfg.HSTS
	if hsts == "" {
		hsts = defaultHSTS
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", referrer)
			h.Set("Permissions-Policy", permissions)
			h.Set("X-XSS-Protection", "1; mode=block")
			if !cfg.HSTSOnlyOverTLS || r.TLS != nil {
				h.Set("Strict-Transport-Security", hsts)
			}
			next.ServeHTTP(w, r)
		})
	}
}
