package webauthn

import (
	"encoding/binary"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

func TestNewDerivesRPIDFromBaseURL(t *testing.T) {
	rp, err := New(Config{DisplayName: "Test", BaseURL: "https://app.example.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if rp.Lib() == nil {
		t.Fatal("Lib() is nil")
	}
}

func TestNewExplicitRPID(t *testing.T) {
	if _, err := New(Config{DisplayName: "Test", BaseURL: "https://app.example.com:8443", RPID: "example.com"}); err != nil {
		t.Fatalf("New with explicit RPID: %v", err)
	}
}

func TestNewBadURL(t *testing.T) {
	if _, err := New(Config{DisplayName: "Test", BaseURL: "://nope"}); err == nil {
		t.Error("expected error for malformed base URL")
	}
}

func TestUserImplementsInterface(t *testing.T) {
	var _ gowebauthn.User = User{}

	u := User{ID: 42, Name: "dave", Credentials: []gowebauthn.Credential{{}}}
	if got := binary.BigEndian.Uint64(u.WebAuthnID()); got != 42 {
		t.Errorf("WebAuthnID round-trip = %d, want 42", got)
	}
	if u.WebAuthnName() != "dave" {
		t.Errorf("WebAuthnName = %q", u.WebAuthnName())
	}
	// DisplayName falls back to Name when unset.
	if u.WebAuthnDisplayName() != "dave" {
		t.Errorf("WebAuthnDisplayName fallback = %q, want dave", u.WebAuthnDisplayName())
	}
	u.DisplayName = "Dave S"
	if u.WebAuthnDisplayName() != "Dave S" {
		t.Errorf("WebAuthnDisplayName = %q, want Dave S", u.WebAuthnDisplayName())
	}
	if len(u.WebAuthnCredentials()) != 1 {
		t.Error("WebAuthnCredentials should return the one credential")
	}
	if u.WebAuthnIcon() != "" {
		t.Error("WebAuthnIcon should be empty")
	}
}
