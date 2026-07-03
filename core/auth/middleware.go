package auth

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// RequireAuth requires a valid session. Unauthenticated requests are redirected
// to the configured login path with a `return` parameter carrying the original
// URL. The authenticated user is installed on the request context
// (GetUserFromContext). In `-tags dev` builds with the dev bypass enabled, a
// loopback request is auto-authenticated as the seeded dev user.
func (m *Manager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if devUser, ok := tryDevBypass(m, r); ok {
			next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), devUser)))
			return
		}

		user, err := m.GetUser(r)
		if err != nil {
			returnURL := r.URL.Path
			if r.URL.RawQuery != "" {
				returnURL += "?" + r.URL.RawQuery
			}
			redirectURL := m.loginPath
			if returnURL != "/" && returnURL != "" {
				redirectURL += "?return=" + url.QueryEscape(returnURL)
			}
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), user)))
	})
}

// RequireCSRF validates the CSRF token on state-changing requests
// (POST/PUT/DELETE/PATCH). Other methods pass through.
func (m *Manager) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			if err := m.ValidateCSRFToken(r); err != nil {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePasswordChange forces a user flagged MustChangePassword to setupPath
// before any other page. Place it AFTER RequireAuth in the chain. Requests to
// setupPath itself, to any of allowExact paths, and to anything under /static/
// pass through so the user can actually complete the change and assets load.
func (m *Manager) RequirePasswordChange(setupPath string, allowExact ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowExact)+1)
	allowed[setupPath] = true
	for _, p := range allowExact {
		allowed[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				http.Redirect(w, r, m.loginPath, http.StatusSeeOther)
				return
			}
			// Match on the cleaned path: net/http does NOT normalize `..`
			// before middleware runs, so without Clean a request for
			// /static/../account would satisfy the /static/ prefix here while
			// a normalizing router routes it to /account — an allowlist
			// bypass of the must-change gate.
			p := path.Clean(r.URL.Path)
			if allowed[p] || strings.HasPrefix(p, "/static/") {
				next.ServeHTTP(w, r)
				return
			}
			if user.MustChangePassword() {
				http.Redirect(w, r, setupPath, http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
