//go:build dev

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDevBypassRequiresEnvVar(t *testing.T) {
	store := newStore()
	mkUser(t, store, "dev", "dev", "correct horse battery staple")
	m, _ := NewManager(ManagerConfig{
		Store: store, SessionSecret: testSecret, Timeout: time.Hour,
		DevBypassEnvVar: "WEBCORE_TEST_DEV_LOGIN",
	})

	// Env var unset → bypass declines even on loopback.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	if _, ok := tryDevBypass(m, req); ok {
		t.Fatal("bypass should decline when env var is unset")
	}

	// Enable env var.
	t.Setenv("WEBCORE_TEST_DEV_LOGIN", "1")

	// Loopback → bypass fires as the dev user.
	if u, ok := tryDevBypass(m, req); !ok || u.ID() != "dev" {
		t.Fatalf("loopback bypass should log in as dev, got ok=%v", ok)
	}

	// Non-loopback → declines.
	remote := httptest.NewRequest(http.MethodGet, "/", nil)
	remote.RemoteAddr = "203.0.113.9:5555"
	if _, ok := tryDevBypass(m, remote); ok {
		t.Fatal("bypass should decline for non-loopback remote")
	}
}

func TestDevBypassDeclinesMissingUser(t *testing.T) {
	store := newStore() // no dev user seeded
	m, _ := NewManager(ManagerConfig{
		Store: store, SessionSecret: testSecret, Timeout: time.Hour,
		DevBypassEnvVar: "WEBCORE_TEST_DEV_LOGIN2",
	})
	t.Setenv("WEBCORE_TEST_DEV_LOGIN2", "1")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	if _, ok := tryDevBypass(m, req); ok {
		t.Fatal("bypass should decline when dev user is absent")
	}
}
