//go:build dev

// Dev-only loopback auto-login bypass. Compiled in ONLY when the binary is
// built with `-tags dev`. Production build paths must omit the tag, so this
// file and its symbols never enter a release binary — there is no codepath,
// env-var check, or loopback check to exploit in production.

package auth

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
)

var devBypassBannerOnce sync.Once

// tryDevBypass returns the configured dev user when ALL of these hold:
//
//  1. The binary was built with `-tags dev` (this file compiled in).
//  2. The Manager's DevBypassEnvVar is set to "1" in the environment.
//  3. r.RemoteAddr is a loopback address.
//  4. The dev account exists in the store and its StatusError() is nil.
//
// The app is responsible for seeding the dev account (webcore never creates
// users). In production builds the sibling stub returns (nil, false).
func tryDevBypass(m *Manager, r *http.Request) (AuthUser, bool) {
	if os.Getenv(m.devBypassEnvVar) != "1" {
		return nil, false
	}
	if !requestIsLoopback(r) {
		return nil, false
	}
	user, err := normalizeUser(m.store.GetUserByEmail(m.devBypassEmail))
	if err != nil || user == nil {
		m.logger.Warn("dev auto-login: dev user missing; bypass inactive",
			"user", m.devBypassEmail, "error", err)
		return nil, false
	}
	if statusErr := user.StatusError(); statusErr != nil {
		m.logger.Warn("dev auto-login: dev user not permitted; bypass inactive", "error", statusErr)
		return nil, false
	}
	return user, true
}

// requestIsLoopback reports whether r.RemoteAddr is a loopback IP. If a proxy
// rewrites RemoteAddr (e.g. chi RealIP from X-Forwarded-For), a proxied request
// surfaces the proxy's IP here — intended: only direct loopback requests pass.
func requestIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// LogDevBypassStartupBanner emits a loud, unmissable warning at startup when
// the dev auto-login bypass is potentially active. Production builds replace
// this with a no-op.
func LogDevBypassStartupBanner(m *Manager, logger *slog.Logger) {
	if os.Getenv(m.devBypassEnvVar) != "1" {
		logger.Info("dev auto-login: bypass compiled in (`-tags dev`) but disabled — set " + m.devBypassEnvVar + "=1 to enable")
		return
	}
	devBypassBannerOnce.Do(func() {
		logger.Warn("==========================================================")
		logger.Warn("dev auto-login ACTIVE — loopback requests log in as the dev user")
		logger.Warn("DO NOT USE IN PRODUCTION. Rebuild without `-tags dev` to remove entirely.")
		logger.Warn("==========================================================")
	})
}
