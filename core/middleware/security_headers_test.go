package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(cfg Config, tlsConn bool) *httptest.ResponseRecorder {
	h := SecurityHeaders(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if tlsConn {
		req.TLS = &tls.ConnectionState{}
	} else {
		// httptest.NewRequest auto-populates req.TLS for https:// targets;
		// clear it so the "plain HTTP" path is actually exercised.
		req.TLS = nil
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestDefaultHeaders(t *testing.T) {
	w := serve(Config{}, false)
	hdr := w.Header()
	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        defaultReferrerPolicy,
		"Permissions-Policy":     defaultPermissionsPolicy,
		"X-XSS-Protection":       "1; mode=block",
	}
	for k, want := range checks {
		if got := hdr.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "cdn.tailwindcss.com") {
		t.Errorf("default CSP should allow CDN, got %q", hdr.Get("Content-Security-Policy"))
	}
}

func TestLocalAssetsCSPIsStrict(t *testing.T) {
	w := serve(Config{LocalAssets: true}, false)
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "cdn.tailwindcss.com") || strings.Contains(csp, "unpkg.com") {
		t.Errorf("local-assets CSP must not allow CDN origins, got %q", csp)
	}
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("local CSP missing self script-src, got %q", csp)
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	if got := serve(Config{HSTSOnlyOverTLS: true}, false).Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("plain HTTP should omit HSTS, got %q", got)
	}
	if got := serve(Config{HSTSOnlyOverTLS: true}, true).Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("TLS connection should set HSTS")
	}
	// Default (always-on) sets HSTS even on plain HTTP.
	if got := serve(Config{}, false).Header().Get("Strict-Transport-Security"); got != defaultHSTS {
		t.Errorf("default HSTS = %q, want %q", got, defaultHSTS)
	}
}

func TestExplicitDirectivesOverride(t *testing.T) {
	w := serve(Config{Directives: []string{"default-src 'none'"}}, false)
	csp := w.Header().Get("Content-Security-Policy")
	if csp != "default-src 'none'" {
		t.Errorf("explicit Directives should win, got %q", csp)
	}
}

func TestExtraSourcesSanitized(t *testing.T) {
	w := serve(Config{
		LocalAssets: true,
		ExtraSources: []string{
			"connect-src https://api.example.com",      // valid
			"img-src 'self'; script-src 'unsafe-eval'", // injection via ';' — dropped
			"  ",                   // empty — dropped
			"frame-src bad\nthing", // CRLF/control — dropped
		},
	}, false)
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src https://api.example.com") {
		t.Errorf("valid extra source should be included, got %q", csp)
	}
	if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("injection attempt must be dropped, got %q", csp)
	}
}

func TestReportURISanitized(t *testing.T) {
	good := serve(Config{ReportURI: "https://csp.example.com/report"}, false).Header().Get("Content-Security-Policy")
	if !strings.Contains(good, "report-uri https://csp.example.com/report") {
		t.Errorf("valid report-uri should be included, got %q", good)
	}
	for _, bad := range []string{"/relative/path", "javascript:alert(1)", "https://h ost/x"} {
		csp := serve(Config{ReportURI: bad}, false).Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "report-uri") {
			t.Errorf("bad report-uri %q should be dropped, got %q", bad, csp)
		}
	}
}

func TestCustomReferrerAndPermissions(t *testing.T) {
	w := serve(Config{ReferrerPolicy: "no-referrer", PermissionsPolicy: "camera=()"}, false)
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := w.Header().Get("Permissions-Policy"); got != "camera=()" {
		t.Errorf("Permissions-Policy = %q, want camera=()", got)
	}
}
