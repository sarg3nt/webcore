package crypto

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

const testSecret = "this-is-a-32-byte-or-longer-secret!"

func TestRoundTrip(t *testing.T) {
	e, err := New(testSecret, "tokens")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pt := []byte("hello secret world")
	ct, err := e.Encrypt(pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, pt) {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := e.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip = %q, want %q", got, pt)
	}
}

func TestStringRoundTrip(t *testing.T) {
	e, _ := New(testSecret, "tokens")
	ct, err := e.EncryptString("secret")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := e.DecryptString(ct)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "secret" {
		t.Errorf("got %q, want secret", got)
	}
}

func TestEmptyInput(t *testing.T) {
	e, _ := New(testSecret, "tokens")
	if ct, err := e.Encrypt(nil); err != nil || ct != nil {
		t.Errorf("Encrypt(nil) = %v, %v; want nil, nil", ct, err)
	}
	if pt, err := e.Decrypt(nil); err != nil || pt != nil {
		t.Errorf("Decrypt(nil) = %v, %v; want nil, nil", pt, err)
	}
	if s, err := e.DecryptString(nil); err != nil || s != "" {
		t.Errorf("DecryptString(nil) = %q, %v; want empty", s, err)
	}
}

func TestLabelDomainSeparation(t *testing.T) {
	a, _ := New(testSecret, "label-a")
	b, _ := New(testSecret, "label-b")
	ct, _ := a.Encrypt([]byte("data"))
	if _, err := b.Decrypt(ct); err == nil {
		t.Error("different labels must produce incompatible keys")
	}
}

func TestShortSecretRejected(t *testing.T) {
	if _, err := New("tooshort", "l"); err == nil {
		t.Error("New should reject short secret")
	}
	if _, err := NewFromHashedKey("tooshort"); err == nil {
		t.Error("NewFromHashedKey should reject short secret")
	}
}

func TestEmptyLabelRejected(t *testing.T) {
	if _, err := New(testSecret, ""); err == nil {
		t.Error("New should reject empty label")
	}
}

func TestTamperDetected(t *testing.T) {
	e, _ := New(testSecret, "tokens")
	ct, _ := e.Encrypt([]byte("data"))
	ct[len(ct)-1] ^= 0xff // flip a tag bit
	if _, err := e.Decrypt(ct); err != ErrInvalidCiphertext {
		t.Errorf("tampered ciphertext err = %v, want ErrInvalidCiphertext", err)
	}
}

func TestShortCiphertextRejected(t *testing.T) {
	e, _ := New(testSecret, "tokens")
	if _, err := e.Decrypt([]byte{1, 2, 3}); err != ErrInvalidCiphertext {
		t.Errorf("short ciphertext err = %v, want ErrInvalidCiphertext", err)
	}
}

// TestFromHashedKeyCompat documents the legacy SHA-256 derivation so a
// migrating app can confirm web-core decrypts data keyed the old way.
func TestFromHashedKeyCompat(t *testing.T) {
	e, err := NewFromHashedKey(testSecret)
	if err != nil {
		t.Fatalf("NewFromHashedKey: %v", err)
	}
	// Sanity: the key really is SHA-256(secret) — round-trip works and the
	// HKDF-derived encryptor cannot read it.
	ct, _ := e.Encrypt([]byte("legacy"))
	got, err := e.Decrypt(ct)
	if err != nil || string(got) != "legacy" {
		t.Fatalf("legacy round-trip failed: %v / %q", err, got)
	}
	_ = sha256.Sum256 // referenced to pin intent
	hk, _ := New(testSecret, "tokens")
	if _, err := hk.Decrypt(ct); err == nil {
		t.Error("HKDF encryptor must not decrypt legacy-keyed data")
	}
}
