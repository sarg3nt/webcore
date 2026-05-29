package auth

import (
	"encoding/hex"
	"testing"
)

func TestGenerateUUIDUnique(t *testing.T) {
	a, b := GenerateUUID(), GenerateUUID()
	if a == b {
		t.Error("UUIDs should be unique")
	}
	if len(a) != 36 {
		t.Errorf("UUID length = %d, want 36", len(a))
	}
}

func TestGenerateSessionToken(t *testing.T) {
	tok, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	raw, err := hex.DecodeString(tok)
	if err != nil {
		t.Fatalf("token not hex: %v", err)
	}
	if len(raw) != 16 {
		t.Errorf("session token = %d bytes, want 16 (128-bit)", len(raw))
	}
}

func TestGenerateCSRFToken(t *testing.T) {
	tok, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken: %v", err)
	}
	raw, _ := hex.DecodeString(tok)
	if len(raw) != 32 {
		t.Errorf("CSRF token = %d bytes, want 32 (256-bit)", len(raw))
	}
}

func TestGenerateSecureTokenMinLength(t *testing.T) {
	// Asking for fewer than MinTokenBytes is bumped up to the minimum.
	tok, err := GenerateSecureToken(4)
	if err != nil {
		t.Fatalf("GenerateSecureToken: %v", err)
	}
	if len(tok) == 0 {
		t.Error("token should be non-empty")
	}
	a, _ := GenerateSecureToken(32)
	b, _ := GenerateSecureToken(32)
	if a == b {
		t.Error("secure tokens should be unique")
	}
}

func TestValidateEmail(t *testing.T) {
	good := []string{"dave@sarg3.net", "admin"}
	for _, e := range good {
		if err := ValidateEmail(e); err != nil {
			t.Errorf("ValidateEmail(%q) = %v, want nil", e, err)
		}
	}
	bad := []string{"", "not-an-email", "Dave <dave@sarg3.net>"}
	for _, e := range bad {
		if err := ValidateEmail(e); err == nil {
			t.Errorf("ValidateEmail(%q) = nil, want error", e)
		}
	}
}
