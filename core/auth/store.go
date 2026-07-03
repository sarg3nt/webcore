package auth

import (
	"net/http"
	"reflect"
	"time"
)

// AuthUser is the minimal view of a user that the Manager needs. The consuming
// app's user model implements it. IDs are strings — apps with integer primary
// keys stringify at this boundary (no schema change required), and apps that
// use UUIDs (recommended, non-enumerable) return them directly.
type AuthUser interface {
	// ID is the stable user identifier stored in the session cookie.
	ID() string
	// Email is the login identifier.
	Email() string
	// PasswordHash is the bcrypt hash to compare against, or "" if the user
	// has no password (CheckPassword handles the empty case in constant time).
	PasswordHash() string
	// IsLocked reports whether the account is currently locked out (e.g. too
	// many failed attempts). Apps without lockout return false.
	IsLocked() bool
	// StatusError returns a non-nil, user-facing error when the account exists
	// but may not log in (pending approval, disabled, …); nil means the
	// account is permitted to authenticate. Apps with only active users return
	// nil.
	//
	// Enumeration note: Login surfaces this message verbatim and BEFORE the
	// password check, so a non-generic message ("pending approval") tells an
	// unauthenticated caller the account exists and why it can't log in. That
	// is usually the desired UX; if enumeration resistance matters more, keep
	// the message generic.
	StatusError() error
	// MustChangePassword reports whether the user must set a new password
	// before proceeding. Apps without this gate return false.
	MustChangePassword() bool
}

// UserStore is the persistence the Manager drives. Implementations back it with
// the app's own database.
//
// IMPORTANT: the "by lookup" methods must return a nil AuthUser (the untyped
// interface nil, not a typed nil pointer) AND a nil error when no row matches.
// The Manager distinguishes "not found" from "error" by the nil interface, so
// returning a typed-nil pointer would defeat the check.
type UserStore interface {
	// GetUserByEmail returns the user with the given email, or (nil, nil) when
	// none exists.
	GetUserByEmail(email string) (AuthUser, error)
	// GetUserByID returns the user with the given id, or (nil, nil) when none
	// exists.
	GetUserByID(id string) (AuthUser, error)
	// GetUserByResetToken returns the user owning a valid (unexpired) password
	// reset token, or (nil, nil) when none matches.
	GetUserByResetToken(token string) (AuthUser, error)

	// RecordLoginAttempt records a login attempt outcome for lockout/rate
	// accounting.
	RecordLoginAttempt(id string, success bool) error

	// SetSessionToken stores the server-side session token (with client
	// metadata) for the user, replacing any previous token.
	SetSessionToken(id, token, ip, userAgent string) error
	// ValidateSessionToken reports whether token is the user's current
	// server-side session token.
	ValidateSessionToken(id, token string) (bool, error)
	// ClearSessionToken invalidates the user's server-side session (logout,
	// password change).
	ClearSessionToken(id string) error

	// UpdatePassword sets a new password hash and the must-change flag.
	UpdatePassword(id, hash string, mustChange bool) error
	// SetPasswordResetToken stores a reset token with its expiry for the user.
	SetPasswordResetToken(id, token string, expiresAt time.Time) error
}

// AuditLogger is an optional sink for security-relevant events. Pass one to the
// Manager to record logins, logouts, and password changes; a nil AuditLogger
// disables audit logging.
type AuditLogger interface {
	// LogAudit records an action. userID may be nil for pre-authentication
	// events. action is one of the Action* constants; details is free-form.
	LogAudit(r *http.Request, userID *string, action, details string)
}

// Audit action constants passed to AuditLogger.LogAudit. Apps map these to
// their own audit schema as needed.
const (
	ActionLogin          = "login"
	ActionLoginFailed    = "login_failed"
	ActionLogout         = "logout"
	ActionPasswordChange = "password_change"
	ActionPasswordReset  = "password_reset"
)

// normalizeUser guards the Manager against the typed-nil interface trap: a
// UserStore implemented as `var u *AppUser; return u, nil` returns a NON-nil
// AuthUser interface wrapping a nil pointer, which would sail past every
// `user == nil` not-found check and later panic — or, with a buggy
// ValidateSessionToken, mis-authenticate — on first use. Every store lookup
// is routed through here so a typed-nil collapses to the untyped nil the
// UserStore contract requires.
func normalizeUser(u AuthUser, err error) (AuthUser, error) {
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, nil
	}
	v := reflect.ValueOf(u)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		if v.IsNil() {
			return nil, nil
		}
	}
	return u, nil
}
