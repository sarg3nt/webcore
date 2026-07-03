package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"
)

// typedNilStore mis-implements the UserStore contract by returning a typed-nil
// *fakeUser (non-nil interface, nil pointer) for every lookup — the classic Go
// trap the contract warns about. The Manager must treat it as "not found", not
// panic or mis-authenticate.
type typedNilStore struct{ fakeStore }

func (s *typedNilStore) GetUserByEmail(string) (AuthUser, error) {
	var u *fakeUser
	return u, nil // typed nil wrapped in the interface
}

func (s *typedNilStore) GetUserByID(string) (AuthUser, error) {
	var u *fakeUser
	return u, nil
}

func (s *typedNilStore) GetUserByResetToken(string) (AuthUser, error) {
	var u *fakeUser
	return u, nil
}

func newTypedNilManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(ManagerConfig{
		Store:         &typedNilStore{},
		SessionSecret: testSecret,
		Timeout:       time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestLoginTypedNilUserTreatedAsNotFound(t *testing.T) {
	m := newTypedNilManager(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	_, err := m.Login(w, req, "anyone@example.com", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("typed-nil user: err = %v, want ErrInvalidCredentials (no panic, no bypass)", err)
	}
}

func TestResetPasswordTypedNilTreatedAsInvalidToken(t *testing.T) {
	m := newTypedNilManager(t)
	req := httptest.NewRequest(http.MethodPost, "/reset", nil)
	if err := m.ResetPassword(req, "sometoken", "brand new passphrase here 77"); err == nil {
		t.Error("typed-nil reset-token user should be an invalid-token error")
	}
}

// TestRequirePasswordChangePathTraversal guards the allowlist against
// un-normalized paths: /static/../dashboard must NOT satisfy the /static/
// prefix and skip the must-change gate.
func TestRequirePasswordChangePathTraversal(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	u := &fakeUser{id: "u1", email: "dave@sarg3.net", mustChange: true}
	h := m.RequirePasswordChange("/setup")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/static/../dashboard", nil)
	// httptest normalizes the URL when parsing the target string; force the
	// raw un-cleaned path the way a hostile client sends it.
	req.URL.Path = "/static/../dashboard"
	req = req.WithContext(ContextWithUser(req.Context(), u))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("traversal path = %d, want 303 redirect to setup (allowlist bypass regression)", w.Code)
	}
	// Sanity: the cleaned form really is outside /static/.
	if p := path.Clean("/static/../dashboard"); p != "/dashboard" {
		t.Fatalf("test premise broken: Clean = %q", p)
	}
}
