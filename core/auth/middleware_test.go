package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestRequireAuthRedirectsAnon(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	h := m.RequireAuth(okNext())

	req := httptest.NewRequest(http.MethodGet, "/secret?x=1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?return=") {
		t.Errorf("redirect = %q, want /login?return=...", loc)
	}
	if !strings.Contains(loc, "%2Fsecret%3Fx%3D1") {
		t.Errorf("redirect should carry escaped return URL, got %q", loc)
	}
}

func TestRequireAuthPassesAndInjectsUser(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "dave@sarg3.net", "correct horse battery staple")

	var gotID string
	h := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := GetUserFromContext(r.Context()); ok {
			gotID = u.ID()
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotID != "u1" {
		t.Errorf("context user = %q, want u1", gotID)
	}
}

func TestRequireCSRF(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	mkUser(t, store, "u1", "dave@sarg3.net", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "dave@sarg3.net", "correct horse battery staple")

	// Need the CSRF token from the session.
	gr := httptest.NewRequest(http.MethodGet, "/", nil)
	gr.AddCookie(cookie)
	token, err := m.GetCSRFToken(gr)
	if err != nil {
		t.Fatalf("GetCSRFToken: %v", err)
	}

	h := m.RequireCSRF(okNext())

	// GET passes without token.
	get := httptest.NewRequest(http.MethodGet, "/", nil)
	gw := httptest.NewRecorder()
	h.ServeHTTP(gw, get)
	if gw.Code != http.StatusOK {
		t.Errorf("GET should pass, got %d", gw.Code)
	}

	// POST without token → 403.
	bad := httptest.NewRequest(http.MethodPost, "/", nil)
	bad.AddCookie(cookie)
	bw := httptest.NewRecorder()
	h.ServeHTTP(bw, bad)
	if bw.Code != http.StatusForbidden {
		t.Errorf("POST without token = %d, want 403", bw.Code)
	}

	// POST with valid token → pass.
	good := httptest.NewRequest(http.MethodPost, "/", nil)
	good.AddCookie(cookie)
	good.Header.Set("X-CSRF-Token", token)
	gw2 := httptest.NewRecorder()
	h.ServeHTTP(gw2, good)
	if gw2.Code != http.StatusOK {
		t.Errorf("POST with valid token = %d, want 200", gw2.Code)
	}
}

func TestRequirePasswordChange(t *testing.T) {
	store := newStore()
	m := newManager(t, store)
	u := &fakeUser{id: "u1", email: "dave@sarg3.net", mustChange: true}

	mw := m.RequirePasswordChange("/setup", "/logout")

	// User flagged must-change, hitting a normal page → redirect to /setup.
	h := mw(okNext())
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req = req.WithContext(ContextWithUser(req.Context(), u))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" {
		t.Errorf("must-change user should redirect to /setup, got %d %q", w.Code, w.Header().Get("Location"))
	}

	// The setup page itself passes through.
	req2 := httptest.NewRequest(http.MethodGet, "/setup", nil)
	req2 = req2.WithContext(ContextWithUser(req2.Context(), u))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("/setup should pass through, got %d", w2.Code)
	}

	// Static assets pass through.
	req3 := httptest.NewRequest(http.MethodGet, "/static/css/x.css", nil)
	req3 = req3.WithContext(ContextWithUser(req3.Context(), u))
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("/static/* should pass through, got %d", w3.Code)
	}

	// A user NOT flagged passes through anywhere.
	ok := &fakeUser{id: "u2", email: "x@y.z", mustChange: false}
	req4 := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req4 = req4.WithContext(ContextWithUser(req4.Context(), ok))
	w4 := httptest.NewRecorder()
	h.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Errorf("non-flagged user should pass, got %d", w4.Code)
	}
}
