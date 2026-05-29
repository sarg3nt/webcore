package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

// Session cookie value keys.
const (
	sessionUserIDKey = "user_id"
	sessionTokenKey  = "session_token" // server-side-validated token
	sessionLoginKey  = "login_time"    // sliding-window timestamp
	sessionStartKey  = "session_start" // absolute-start timestamp (never refreshed)
	csrfTokenKey     = "csrf_token"
)

// Common errors returned by the Manager. Login deliberately returns the same
// ErrInvalidCredentials for unknown-user, wrong-password, and locked-account
// so the response can't be used to enumerate accounts.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNotAuthenticated   = errors.New("not authenticated")
	ErrSessionExpired     = errors.New("session expired")
)

// ManagerConfig configures a Manager.
type ManagerConfig struct {
	// Store backs all user/session persistence (required).
	Store UserStore
	// SessionSecret keys the cookie store; must be at least 32 bytes.
	SessionSecret string
	// Timeout is the sliding idle timeout, extended on activity (required).
	Timeout time.Duration
	// AbsoluteTimeout is the hard cap measured from login, never extended.
	// Zero disables it (sliding-only).
	AbsoluteTimeout time.Duration
	// Secure sets the cookie Secure flag. Leave false only for non-TLS dev.
	Secure bool
	// SessionName overrides the cookie name (default "web-core-session").
	SessionName string
	// Audit optionally records security events; nil disables audit logging.
	Audit AuditLogger
	// Logger defaults to slog.Default() when nil.
	Logger *slog.Logger
}

// Manager handles authentication and DB-backed session management. The session
// cookie carries a server-side-validated token, so logout and password change
// invalidate sessions immediately and stolen cookies stop working after a
// store wipe.
type Manager struct {
	store           UserStore
	sessionStore    *sessions.CookieStore
	sessionName     string
	timeout         time.Duration
	absoluteTimeout time.Duration
	audit           AuditLogger
	logger          *slog.Logger
}

// NewManager builds a Manager from cfg.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("auth: Store is required")
	}
	if len(cfg.SessionSecret) < 32 {
		return nil, errors.New("auth: session secret must be at least 32 characters")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("auth: Timeout must be positive")
	}
	if cfg.AbsoluteTimeout > 0 && cfg.AbsoluteTimeout < cfg.Timeout {
		return nil, fmt.Errorf("auth: AbsoluteTimeout (%s) must be >= Timeout (%s)", cfg.AbsoluteTimeout, cfg.Timeout)
	}
	name := cfg.SessionName
	if name == "" {
		name = "web-core-session"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(cfg.Timeout.Seconds()),
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSiteStrictMode,
	}

	return &Manager{
		store:           cfg.Store,
		sessionStore:    store,
		sessionName:     name,
		timeout:         cfg.Timeout,
		absoluteTimeout: cfg.AbsoluteTimeout,
		audit:           cfg.Audit,
		logger:          logger,
	}, nil
}

// SetSecure toggles the cookie Secure flag at runtime.
func (m *Manager) SetSecure(secure bool) { m.sessionStore.Options.Secure = secure }

// Login authenticates a user by email + password and establishes a session.
// On any failure to authenticate it returns ErrInvalidCredentials with no
// distinction between unknown user, wrong password, and locked account.
func (m *Manager) Login(w http.ResponseWriter, r *http.Request, email, password string) (AuthUser, error) {
	user, err := m.store.GetUserByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("store error: %w", err)
	}

	// Always run one bcrypt compare regardless of user state to equalize
	// timing between "no such user" and "wrong password".
	hash := ""
	if user != nil {
		hash = user.PasswordHash()
	}
	passwordOK := CheckPassword(password, hash)

	if user == nil {
		return nil, ErrInvalidCredentials
	}

	if user.IsLocked() {
		// Count the probe so an attacker can't poll a locked account for free.
		if err := m.store.RecordLoginAttempt(user.ID(), false); err != nil {
			m.logger.Error("record locked-attempt failed", "error", err, "user_id", user.ID())
		}
		m.logAudit(r, ptr(user.ID()), ActionLoginFailed, "")
		return nil, ErrInvalidCredentials
	}

	if statusErr := user.StatusError(); statusErr != nil {
		return nil, statusErr
	}

	if !passwordOK {
		if err := m.store.RecordLoginAttempt(user.ID(), false); err != nil {
			m.logger.Error("record login attempt failed", "error", err, "user_id", user.ID())
		}
		m.logAudit(r, ptr(user.ID()), ActionLoginFailed, "")
		return nil, ErrInvalidCredentials
	}

	if err := m.store.RecordLoginAttempt(user.ID(), true); err != nil {
		m.logger.Error("record login failed", "error", err, "user_id", user.ID())
	}

	if err := m.establishSession(w, r, user); err != nil {
		return nil, err
	}
	m.logAudit(r, ptr(user.ID()), ActionLogin, "")
	m.logger.Info("user logged in", "user_id", user.ID(), "ip", r.RemoteAddr)
	return user, nil
}

// CreateSessionForUser establishes a session without a password check. Use
// after the user has been authenticated by another means (e.g. WebAuthn).
func (m *Manager) CreateSessionForUser(w http.ResponseWriter, r *http.Request, user AuthUser) error {
	if err := m.establishSession(w, r, user); err != nil {
		return err
	}
	m.logger.Info("session created for user", "user_id", user.ID(), "ip", r.RemoteAddr)
	return nil
}

// establishSession mints a server-side session token + CSRF token and writes
// the session cookie.
func (m *Manager) establishSession(w http.ResponseWriter, r *http.Request, user AuthUser) error {
	sessionToken, err := GenerateSessionToken()
	if err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}
	if err := m.store.SetSessionToken(user.ID(), sessionToken, r.RemoteAddr, r.UserAgent()); err != nil {
		m.logger.Error("store session token failed", "error", err, "user_id", user.ID())
		return fmt.Errorf("create session: %w", err)
	}
	session, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return fmt.Errorf("generate CSRF token: %w", err)
	}
	now := time.Now().Unix()
	session.Values[sessionUserIDKey] = user.ID()
	session.Values[sessionTokenKey] = sessionToken
	session.Values[sessionLoginKey] = now
	session.Values[sessionStartKey] = now
	session.Values[csrfTokenKey] = csrfToken
	if err := session.Save(r, w); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// Logout invalidates the server-side session and clears the cookie.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) error {
	if user, _ := m.GetUser(r); user != nil {
		if err := m.store.ClearSessionToken(user.ID()); err != nil {
			m.logger.Error("clear session token failed", "error", err, "user_id", user.ID())
		}
		m.logAudit(r, ptr(user.ID()), ActionLogout, "")
		m.logger.Info("user logged out", "user_id", user.ID())
	}
	session, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return err
	}
	session.Values = make(map[any]any)
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

// GetUser resolves the authenticated user from the request, validating the
// session token against the store and enforcing both the sliding and absolute
// timeouts. Returns ErrNotAuthenticated / ErrSessionExpired / ErrInvalidCredentials
// (account no longer permitted) on failure.
func (m *Manager) GetUser(r *http.Request) (AuthUser, error) {
	session, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return nil, err
	}
	userID, ok := session.Values[sessionUserIDKey].(string)
	if !ok || userID == "" {
		return nil, ErrNotAuthenticated
	}
	sessionToken, ok := session.Values[sessionTokenKey].(string)
	if !ok || sessionToken == "" {
		return nil, errors.New("invalid session: missing token")
	}

	loginTime, ok := session.Values[sessionLoginKey].(int64)
	if !ok {
		return nil, errors.New("invalid session")
	}
	if time.Since(time.Unix(loginTime, 0)) > m.timeout {
		return nil, ErrSessionExpired
	}
	if m.absoluteTimeout > 0 {
		startUnix, ok := session.Values[sessionStartKey].(int64)
		if !ok {
			startUnix = loginTime // legacy session without an anchor
		}
		if time.Since(time.Unix(startUnix, 0)) > m.absoluteTimeout {
			return nil, ErrSessionExpired
		}
	}

	user, err := m.store.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	valid, err := m.store.ValidateSessionToken(userID, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("session validation: %w", err)
	}
	if !valid {
		return nil, errors.New("session invalid: please log in again")
	}
	if statusErr := user.StatusError(); statusErr != nil {
		return nil, statusErr
	}
	return user, nil
}

// IsAuthenticated reports whether the request carries a valid session.
func (m *Manager) IsAuthenticated(r *http.Request) bool {
	_, err := m.GetUser(r)
	return err == nil
}

// GetCSRFToken returns the CSRF token bound to the current session.
func (m *Manager) GetCSRFToken(r *http.Request) (string, error) {
	session, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return "", err
	}
	token, ok := session.Values[csrfTokenKey].(string)
	if !ok || token == "" {
		return "", errors.New("no CSRF token in session")
	}
	return token, nil
}

// ValidateCSRFToken checks the request's CSRF token (X-CSRF-Token header or
// csrf_token form field) against the session token in constant time.
func (m *Manager) ValidateCSRFToken(r *http.Request) error {
	sessionToken, err := m.GetCSRFToken(r)
	if err != nil {
		return fmt.Errorf("get session CSRF token: %w", err)
	}
	requestToken := r.Header.Get("X-CSRF-Token")
	if requestToken == "" {
		requestToken = r.FormValue("csrf_token")
	}
	if requestToken == "" {
		return errors.New("no CSRF token in request")
	}
	if subtle.ConstantTimeCompare([]byte(requestToken), []byte(sessionToken)) != 1 {
		return errors.New("CSRF token mismatch")
	}
	return nil
}

// ExtendSession slides the idle window forward. It anchors legacy sessions
// missing the absolute-start timestamp and shrinks the cookie MaxAge as the
// hard TTL approaches so the browser also drops the cookie at the boundary.
func (m *Manager) ExtendSession(w http.ResponseWriter, r *http.Request) error {
	session, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return err
	}
	userID, ok := session.Values[sessionUserIDKey].(string)
	if !ok || userID == "" {
		return ErrNotAuthenticated
	}

	// Anchor legacy sessions: capture the current login time as the absolute
	// start before we overwrite it, so the hard TTL can still fire.
	if _, anchored := session.Values[sessionStartKey].(int64); !anchored {
		if loginTime, ok := session.Values[sessionLoginKey].(int64); ok {
			session.Values[sessionStartKey] = loginTime
		}
	}

	if m.absoluteTimeout > 0 {
		if startUnix, ok := session.Values[sessionStartKey].(int64); ok {
			remaining := time.Until(time.Unix(startUnix, 0).Add(m.absoluteTimeout))
			if remaining <= 0 {
				return errors.New("session past absolute timeout")
			}
			maxAge := m.timeout
			if remaining < maxAge {
				maxAge = remaining
			}
			opts := *m.sessionStore.Options // copy so the shared default isn't mutated
			opts.MaxAge = int(maxAge.Seconds())
			session.Options = &opts
		}
	}

	session.Values[sessionLoginKey] = time.Now().Unix()
	return session.Save(r, w)
}

// GetSessionExpirationTime returns when the current session's sliding window
// expires.
func (m *Manager) GetSessionExpirationTime(r *http.Request) (time.Time, error) {
	session, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return time.Time{}, err
	}
	if userID, ok := session.Values[sessionUserIDKey].(string); !ok || userID == "" {
		return time.Time{}, ErrNotAuthenticated
	}
	loginTime, ok := session.Values[sessionLoginKey].(int64)
	if !ok {
		return time.Time{}, errors.New("invalid session")
	}
	return time.Unix(loginTime, 0).Add(m.timeout), nil
}

// ChangePassword verifies the current password and sets a new one, invalidating
// the user's session afterward.
func (m *Manager) ChangePassword(r *http.Request, userID, currentPassword, newPassword string) error {
	user, err := m.store.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if user == nil {
		return errors.New("user not found")
	}
	if !CheckPassword(currentPassword, user.PasswordHash()) {
		return errors.New("current password is incorrect")
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	if CheckPassword(newPassword, user.PasswordHash()) {
		return errors.New("new password must be different from current password")
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := m.store.UpdatePassword(userID, hash, false); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if err := m.store.ClearSessionToken(userID); err != nil {
		m.logger.Error("clear session after password change failed", "error", err)
	}
	m.logAudit(r, ptr(userID), ActionPasswordChange, "")
	return nil
}

// SetPassword sets a new password without checking the current one (forced
// change / admin setup). Does not clear the session.
func (m *Manager) SetPassword(r *http.Request, userID, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := m.store.UpdatePassword(userID, hash, false); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	m.logAudit(r, ptr(userID), ActionPasswordChange, "forced password change")
	return nil
}

// RequestPasswordReset generates and stores a reset token for the email. To
// avoid revealing whether an account exists, it returns ("", nil, nil) when no
// user matches — callers should behave identically either way.
func (m *Manager) RequestPasswordReset(email string) (token string, user AuthUser, err error) {
	user, err = m.store.GetUserByEmail(email)
	if err != nil {
		return "", nil, err
	}
	if user == nil {
		return "", nil, nil
	}
	token, err = GenerateSecureToken(MinTokenBytes)
	if err != nil {
		return "", nil, fmt.Errorf("generate reset token: %w", err)
	}
	if err := m.store.SetPasswordResetToken(user.ID(), token, time.Now().Add(1*time.Hour)); err != nil {
		return "", nil, fmt.Errorf("save reset token: %w", err)
	}
	return token, user, nil
}

// ResetPassword completes a reset using a token issued by RequestPasswordReset.
func (m *Manager) ResetPassword(r *http.Request, token, newPassword string) error {
	user, err := m.store.GetUserByResetToken(token)
	if err != nil {
		return fmt.Errorf("store error: %w", err)
	}
	if user == nil {
		return errors.New("invalid or expired reset token")
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := m.store.UpdatePassword(user.ID(), hash, false); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	m.logAudit(r, ptr(user.ID()), ActionPasswordReset, "via reset link")
	return nil
}

func (m *Manager) logAudit(r *http.Request, userID *string, action, details string) {
	if m.audit == nil {
		return
	}
	m.audit.LogAudit(r, userID, action, details)
}

func ptr(s string) *string { return &s }

// ClientIP extracts the client IP from the request, honoring X-Forwarded-For
// and X-Real-IP (use only behind a trusted proxy that sets them).
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return r.RemoteAddr
}

// ---- Flash messages -------------------------------------------------------

// Flash is a one-shot message rendered on the next page load. Kind is one of
// "success", "error", "warning", "info".
type Flash struct {
	Kind    string
	Message string
}

// AddFlash queues a flash on the session.
func (m *Manager) AddFlash(w http.ResponseWriter, r *http.Request, kind, message string) error {
	session, _ := m.sessionStore.Get(r, m.sessionName)
	session.AddFlash(kind + "\x00" + message)
	return session.Save(r, w)
}

// PopFlashes drains and returns queued flashes, persisting the session so they
// never fire twice.
func (m *Manager) PopFlashes(w http.ResponseWriter, r *http.Request) []Flash {
	session, _ := m.sessionStore.Get(r, m.sessionName)
	raw := session.Flashes()
	if len(raw) == 0 {
		return nil
	}
	_ = session.Save(r, w)
	out := make([]Flash, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		kind, msg := "info", s
		if i := strings.IndexByte(s, '\x00'); i >= 0 {
			kind, msg = s[:i], s[i+1:]
		}
		out = append(out, Flash{Kind: kind, Message: msg})
	}
	return out
}

// ---- Generic session key/value (for in-flight ceremony state, etc.) -------

// PutJSON marshals v and stores it in the session under key.
func (m *Manager) PutJSON(w http.ResponseWriter, r *http.Request, key string, v any) error {
	session, _ := m.sessionStore.Get(r, m.sessionName)
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	session.Values[key] = b
	return session.Save(r, w)
}

// GetJSON unmarshals the bytes stored at key into dst.
func (m *Manager) GetJSON(r *http.Request, key string, dst any) error {
	session, _ := m.sessionStore.Get(r, m.sessionName)
	raw, ok := session.Values[key].([]byte)
	if !ok {
		return fmt.Errorf("session key not found: %s", key)
	}
	return json.Unmarshal(raw, dst)
}

// DeleteKey removes a single session value.
func (m *Manager) DeleteKey(w http.ResponseWriter, r *http.Request, key string) error {
	session, _ := m.sessionStore.Get(r, m.sessionName)
	delete(session.Values, key)
	return session.Save(r, w)
}
