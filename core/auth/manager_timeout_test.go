package auth

// Session-lifetime tests ported from gearbox's pre-webcore auth suite (2026-05
// audit P2-3 and its PR-review follow-ups). They manipulate session internals
// (cookie store, session keys), so they live in-package here now that the
// implementation does.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func timeoutManager(t *testing.T, store *fakeStore, sliding, absolute time.Duration) *Manager {
	t.Helper()
	m, err := NewManager(ManagerConfig{
		Store:           store,
		SessionSecret:   testSecret,
		Timeout:         sliding,
		AbsoluteTimeout: absolute,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// TestGetUserAbsoluteTimeout: a session kept warm by activity must still be
// expired once its absolute lifetime passes. Rewinds the session-start
// timestamp while keeping the sliding-window timestamp fresh.
func TestGetUserAbsoluteTimeout(t *testing.T) {
	store := newStore()
	m := timeoutManager(t, store, time.Hour, time.Hour)
	mkUser(t, store, "u1", "admin", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "admin", "correct horse battery staple")

	// Sanity: valid right after login.
	ok := httptest.NewRequest(http.MethodGet, "/", nil)
	ok.AddCookie(cookie)
	if _, err := m.GetUser(ok); err != nil {
		t.Fatalf("GetUser right after login: %v", err)
	}

	// Rewind session_start past the hard TTL; keep login_time fresh.
	rewind := httptest.NewRequest(http.MethodGet, "/", nil)
	rewind.AddCookie(cookie)
	sess, err := m.sessionStore.Get(rewind, m.sessionName)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	sess.Values[sessionStartKey] = time.Now().Add(-2 * time.Hour).Unix()
	sess.Values[sessionLoginKey] = time.Now().Unix()
	w := httptest.NewRecorder()
	if err := sess.Save(rewind, w); err != nil {
		t.Fatalf("save rewound session: %v", err)
	}
	expired := w.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(expired)
	if _, err := m.GetUser(req); err == nil {
		t.Error("GetUser succeeded past the absolute hard TTL; want expiry")
	}
}

// TestExtendSessionAnchorsLegacySession: a session pre-dating session_start
// must be anchored on the next ExtendSession, not slide forever via the
// login-time fallback.
func TestExtendSessionAnchorsLegacySession(t *testing.T) {
	store := newStore()
	m := timeoutManager(t, store, time.Hour, 24*time.Hour)
	mkUser(t, store, "u1", "admin", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "admin", "correct horse battery staple")

	// Strip session_start to simulate a legacy session.
	strip := httptest.NewRequest(http.MethodGet, "/", nil)
	strip.AddCookie(cookie)
	sess, err := m.sessionStore.Get(strip, m.sessionName)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	delete(sess.Values, sessionStartKey)
	sw := httptest.NewRecorder()
	if err := sess.Save(strip, sw); err != nil {
		t.Fatalf("save stripped session: %v", err)
	}
	legacy := sw.Result().Cookies()[0]

	ext := httptest.NewRequest(http.MethodPost, "/", nil)
	ext.AddCookie(legacy)
	ew := httptest.NewRecorder()
	if err := m.ExtendSession(ew, ext); err != nil {
		t.Fatalf("ExtendSession: %v", err)
	}
	anchoredCookie := ew.Result().Cookies()[0]

	read := httptest.NewRequest(http.MethodGet, "/", nil)
	read.AddCookie(anchoredCookie)
	anchored, err := m.sessionStore.Get(read, m.sessionName)
	if err != nil {
		t.Fatalf("read anchored session: %v", err)
	}
	if _, ok := anchored.Values[sessionStartKey].(int64); !ok {
		t.Error("session_start missing after ExtendSession; legacy session unanchored")
	}
}

// TestExtendSessionCookieMaxAgeShrinks: the per-save cookie MaxAge shrinks as
// the hard TTL approaches so the browser drops the cookie at the absolute
// boundary rather than a full sliding window after the last save.
func TestExtendSessionCookieMaxAgeShrinks(t *testing.T) {
	store := newStore()
	m := timeoutManager(t, store, time.Hour, time.Hour)
	mkUser(t, store, "u1", "admin", "correct horse battery staple")
	cookie := loginRoundTrip(t, m, "admin", "correct horse battery staple")

	// Rewind session_start to 30 minutes ago: ~30m left on the hard TTL.
	rewind := httptest.NewRequest(http.MethodGet, "/", nil)
	rewind.AddCookie(cookie)
	sess, err := m.sessionStore.Get(rewind, m.sessionName)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	sess.Values[sessionStartKey] = time.Now().Add(-30 * time.Minute).Unix()
	rw := httptest.NewRecorder()
	if err := sess.Save(rewind, rw); err != nil {
		t.Fatalf("save rewound session: %v", err)
	}
	mid := rw.Result().Cookies()[0]

	ext := httptest.NewRequest(http.MethodPost, "/", nil)
	ext.AddCookie(mid)
	ew := httptest.NewRecorder()
	if err := m.ExtendSession(ew, ext); err != nil {
		t.Fatalf("ExtendSession: %v", err)
	}
	out := ew.Result().Cookies()[0]

	// ~1800s remaining absolute, not the 3600s sliding window; 10s jitter.
	if out.MaxAge < 1700 || out.MaxAge > 1810 {
		t.Errorf("Set-Cookie MaxAge=%d, want ~1800 (remaining absolute TTL), not 3600 (sliding)", out.MaxAge)
	}
}
