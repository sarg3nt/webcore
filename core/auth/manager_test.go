package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeUser implements AuthUser.
type fakeUser struct {
	id         string
	email      string
	hash       string
	locked     bool
	statusErr  error
	mustChange bool
}

func (u *fakeUser) ID() string               { return u.id }
func (u *fakeUser) Email() string            { return u.email }
func (u *fakeUser) PasswordHash() string     { return u.hash }
func (u *fakeUser) IsLocked() bool           { return u.locked }
func (u *fakeUser) StatusError() error       { return u.statusErr }
func (u *fakeUser) MustChangePassword() bool { return u.mustChange }

// fakeStore implements UserStore in memory.
type fakeStore struct {
	mu          sync.Mutex
	byEmail     map[string]*fakeUser
	byID        map[string]*fakeUser
	tokens      map[string]string // userID -> session token
	resetTokens map[string]string // token -> userID
	attempts    []bool
}

func newStore() *fakeStore {
	return &fakeStore{
		byEmail:     map[string]*fakeUser{},
		byID:        map[string]*fakeUser{},
		tokens:      map[string]string{},
		resetTokens: map[string]string{},
	}
}

func (s *fakeStore) add(u *fakeUser) {
	s.byEmail[u.email] = u
	s.byID[u.id] = u
}

func (s *fakeStore) GetUserByEmail(email string) (AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byEmail[email]; ok {
		return u, nil
	}
	return nil, nil // not found — untyped nil interface
}

func (s *fakeStore) GetUserByID(id string) (AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byID[id]; ok {
		return u, nil
	}
	return nil, nil
}

func (s *fakeStore) GetUserByResetToken(token string) (AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.resetTokens[token]; ok {
		return s.byID[id], nil
	}
	return nil, nil
}

func (s *fakeStore) RecordLoginAttempt(id string, success bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, success)
	return nil
}

func (s *fakeStore) SetSessionToken(id, token, ip, ua string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = token
	return nil
}

func (s *fakeStore) ValidateSessionToken(id, token string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[id] == token && token != "", nil
}

func (s *fakeStore) ClearSessionToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, id)
	return nil
}

func (s *fakeStore) UpdatePassword(id, hash string, mustChange bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byID[id]; ok {
		u.hash = hash
		u.mustChange = mustChange
	}
	return nil
}

func (s *fakeStore) SetPasswordResetToken(id, token string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetTokens[token] = id
	return nil
}

const testSecret = "test-session-secret-at-least-32-bytes-long"

func newManager(t *testing.T, store *fakeStore) *Manager {
	t.Helper()
	m, err := NewManager(ManagerConfig{
		Store:           store,
		SessionSecret:   testSecret,
		Timeout:         time.Hour,
		AbsoluteTimeout: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func mkUser(t *testing.T, store *fakeStore, id, email, password string) *fakeUser {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &fakeUser{id: id, email: email, hash: hash}
	store.add(u)
	return u
}

// loginRoundTrip logs in and returns the resulting Set-Cookie so a follow-up
// request can present the session.
func loginRoundTrip(t *testing.T, m *Manager, email, password string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	w := httptest.NewRecorder()
	if _, err := m.Login(w, req, email, password); err != nil {
		t.Fatalf("Login: %v", err)
	}
	res := w.Result()
	if len(res.Cookies()) == 0 {
		t.Fatal("Login set no cookie")
	}
	return res.Cookies()[0]
}

func TestNewManagerValidation(t *testing.T) {
	if _, err := NewManager(ManagerConfig{SessionSecret: testSecret, Timeout: time.Hour}); err == nil {
		t.Error("missing Store should error")
	}
	if _, err := NewManager(ManagerConfig{Store: newStore(), SessionSecret: "short", Timeout: time.Hour}); err == nil {
		t.Error("short secret should error")
	}
	if _, err := NewManager(ManagerConfig{Store: newStore(), SessionSecret: testSecret, Timeout: time.Hour, AbsoluteTimeout: time.Minute}); err == nil {
		t.Error("absolute < sliding should error")
	}
}

func TestLoginSuccessAndGetUser(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")

	cookie := loginRoundTrip(t, m, "dave@sarg3.net", "correct horse battery staple")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	user, err := m.GetUser(req)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.ID() != "u1" {
		t.Errorf("user ID = %q, want u1", user.ID())
	}
}

func TestLoginUnknownUserGenericError(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	_, err := m.Login(w, req, "nobody@sarg3.net", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWrongPasswordGenericError(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	_, err := m.Login(w, req, "dave@sarg3.net", "wrong password guess")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginLockedGenericError(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	u := mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	u.locked = true
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	_, err := m.Login(w, req, "dave@sarg3.net", "correct horse battery staple")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("locked err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginStatusError(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	u := mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	u.statusErr = errors.New("account is pending approval")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	_, err := m.Login(w, req, "dave@sarg3.net", "correct horse battery staple")
	if err == nil || err.Error() != "account is pending approval" {
		t.Errorf("status err = %v, want pending approval", err)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "dave@sarg3.net", "correct horse battery staple")

	// Logout.
	wreq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	wreq.AddCookie(cookie)
	w := httptest.NewRecorder()
	if err := m.Logout(w, wreq); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	// Old cookie no longer validates (server-side token cleared).
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, err := m.GetUser(req); err == nil {
		t.Error("session should be invalid after logout")
	}
}

func TestCSRFTokenRoundTrip(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "dave@sarg3.net", "correct horse battery staple")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	token, err := m.GetCSRFToken(req)
	if err != nil {
		t.Fatalf("GetCSRFToken: %v", err)
	}

	// Valid token in header passes.
	post := httptest.NewRequest(http.MethodPost, "/action", nil)
	post.AddCookie(cookie)
	post.Header.Set("X-CSRF-Token", token)
	if err := m.ValidateCSRFToken(post); err != nil {
		t.Errorf("valid CSRF token should pass: %v", err)
	}
	// Wrong token fails.
	bad := httptest.NewRequest(http.MethodPost, "/action", nil)
	bad.AddCookie(cookie)
	bad.Header.Set("X-CSRF-Token", "deadbeef")
	if err := m.ValidateCSRFToken(bad); err == nil {
		t.Error("wrong CSRF token should fail")
	}
}

func TestChangePasswordInvalidatesSession(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "dave@sarg3.net", "correct horse battery staple")

	req := httptest.NewRequest(http.MethodPost, "/pw", nil)
	if err := m.ChangePassword(req, "u1", "correct horse battery staple", "totally different passphrase 99"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	// Session token cleared → old cookie invalid.
	g := httptest.NewRequest(http.MethodGet, "/", nil)
	g.AddCookie(cookie)
	if _, err := m.GetUser(g); err == nil {
		t.Error("session should be invalid after password change")
	}
	// New password works for login.
	w := httptest.NewRecorder()
	lr := httptest.NewRequest(http.MethodPost, "/login", nil)
	if _, err := m.Login(w, lr, "dave@sarg3.net", "totally different passphrase 99"); err != nil {
		t.Errorf("login with new password failed: %v", err)
	}
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	req := httptest.NewRequest(http.MethodPost, "/pw", nil)
	if err := m.ChangePassword(req, "u1", "wrong current", "totally different passphrase 99"); err == nil {
		t.Error("wrong current password should fail")
	}
}

func TestPasswordResetFlow(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")

	token, user, err := m.RequestPasswordReset("dave@sarg3.net")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if user == nil || token == "" {
		t.Fatal("expected token + user for known email")
	}
	req := httptest.NewRequest(http.MethodPost, "/reset", nil)
	if err := m.ResetPassword(req, token, "brand new passphrase here 77"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	w := httptest.NewRecorder()
	lr := httptest.NewRequest(http.MethodPost, "/login", nil)
	if _, err := m.Login(w, lr, "dave@sarg3.net", "brand new passphrase here 77"); err != nil {
		t.Errorf("login after reset failed: %v", err)
	}
}

func TestRequestPasswordResetUnknownEmailSilent(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	token, user, err := m.RequestPasswordReset("nobody@sarg3.net")
	if err != nil || token != "" || user != nil {
		t.Errorf("unknown email should return empty silently, got token=%q user=%v err=%v", token, user, err)
	}
}

func TestFlashRoundTrip(t *testing.T) {
	store := newStore()
	m := newManager(t, store)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := m.AddFlash(w, req, "success", "saved!"); err != nil {
		t.Fatalf("AddFlash: %v", err)
	}
	cookie := w.Result().Cookies()[0]

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)
	w2 := httptest.NewRecorder()
	flashes := m.PopFlashes(w2, req2)
	if len(flashes) != 1 || flashes[0].Kind != "success" || flashes[0].Message != "saved!" {
		t.Fatalf("flashes = %+v, want one success/saved!", flashes)
	}
}

func TestCreateSessionForUser(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	u := mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := m.CreateSessionForUser(w, req, u); err != nil {
		t.Fatalf("CreateSessionForUser: %v", err)
	}
	cookie := w.Result().Cookies()[0]
	g := httptest.NewRequest(http.MethodGet, "/", nil)
	g.AddCookie(cookie)
	if !m.IsAuthenticated(g) {
		t.Error("session created for user should authenticate")
	}
}
