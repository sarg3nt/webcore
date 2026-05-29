// Package crypto provides AES-256-GCM authenticated encryption for at-rest
// secrets (session tokens, API keys, identity blobs) stored in a database.
//
// The recommended constructor is New(masterSecret, label), which derives an
// independent 256-bit subkey from the master secret using HKDF-SHA256 keyed by
// the label. Different labels produce cryptographically independent keys from
// one master secret, giving domain separation between unrelated secret stores
// (e.g. "audible-tokens" vs "agent-keys") without managing multiple master
// secrets.
//
// The wire format in every case is nonce || ciphertext || tag, exactly what
// crypto/cipher's GCM Seal produces with the nonce prepended.
//
// NewFromHashedKey is a compatibility constructor for data originally
// encrypted with a key derived as a bare SHA-256 of the secret (no HKDF, no
// label). New code should prefer New; NewFromHashedKey exists so an app
// migrating onto web-core can keep reading its existing at-rest data without a
// re-encryption pass.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

const minSecretLen = 32

var (
	// ErrInvalidKey is returned when the master secret is too short.
	ErrInvalidKey = errors.New("invalid encryption key")
	// ErrInvalidCiphertext is returned when ciphertext is malformed or fails
	// authentication.
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// Encryptor performs AES-256-GCM encryption/decryption over a fixed key.
// The AEAD is built once and reused — Encryptor is safe for concurrent use.
type Encryptor struct {
	gcm cipher.AEAD
}

// New derives a subkey from the master secret using HKDF-SHA256 keyed by the
// supplied label, then returns an AES-256-GCM encryptor over that subkey.
// Different labels produce independent keys. The master secret must be at
// least 32 bytes; the label must be non-empty.
func New(masterSecret, label string) (*Encryptor, error) {
	if len(masterSecret) < minSecretLen {
		return nil, fmt.Errorf("%w: master secret must be at least %d bytes, got %d", ErrInvalidKey, minSecretLen, len(masterSecret))
	}
	if label == "" {
		return nil, errors.New("label is required")
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(masterSecret), nil, []byte(label))
	if _, err := r.Read(key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return newWithKey(key)
}

// NewFromHashedKey returns an encryptor whose key is the SHA-256 of the secret,
// with no HKDF and no label. This is the legacy derivation; prefer New for new
// code. The secret must be at least 32 bytes.
func NewFromHashedKey(secret string) (*Encryptor, error) {
	if len(secret) < minSecretLen {
		return nil, ErrInvalidKey
	}
	hash := sha256.Sum256([]byte(secret))
	return newWithKey(hash[:])
}

func newWithKey(key []byte) (*Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Encryptor{gcm: gcm}, nil
}

// Encrypt returns nonce || ciphertext || tag. Empty plaintext returns a nil
// slice so callers can round-trip "no value" without storing a nonce.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt parses nonce || ciphertext || tag and returns the plaintext. Empty
// input returns a nil slice (the inverse of Encrypt's empty-input behavior).
func (e *Encryptor) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	ns := e.gcm.NonceSize()
	if len(blob) < ns+e.gcm.Overhead() {
		return nil, ErrInvalidCiphertext
	}
	nonce, ct := blob[:ns], blob[ns:]
	plaintext, err := e.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

// EncryptString is a convenience wrapper over Encrypt for string plaintext.
func (e *Encryptor) EncryptString(plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	return e.Encrypt([]byte(plaintext))
}

// DecryptString is a convenience wrapper over Decrypt returning a string.
func (e *Encryptor) DecryptString(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", nil
	}
	plaintext, err := e.Decrypt(blob)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
