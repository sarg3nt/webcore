//go:build !dev

// Production sibling to dev_bypass_on.go, compiled in for every build WITHOUT
// `-tags dev`. All entry points are no-ops: the dev auto-login bypass is not
// present in the binary at all — no codepath, no env check, nothing to exploit.

package auth

import (
	"log/slog"
	"net/http"
)

func tryDevBypass(_ *Manager, _ *http.Request) (AuthUser, bool) { return nil, false }

// LogDevBypassStartupBanner is a no-op in production builds.
func LogDevBypassStartupBanner(_ *Manager, _ *slog.Logger) {}
