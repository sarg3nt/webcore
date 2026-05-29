package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"

	"github.com/google/uuid"
)

// MinTokenBytes is the minimum random length (256 bits) for GenerateSecureToken.
const MinTokenBytes = 32

// GenerateUUID returns a new UUID v4, suitable for non-enumerable user IDs.
func GenerateUUID() string {
	return uuid.New().String()
}

// GenerateSessionToken returns a 128-bit hex session token. Stored server-side
// and validated on each request (OWASP recommends >= 128 bits).
func GenerateSessionToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateCSRFToken returns a 256-bit hex CSRF token.
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateSecureToken returns a base64url token of length random bytes (raised
// to MinTokenBytes if smaller). Used for password-reset and similar tokens.
func GenerateSecureToken(length int) (string, error) {
	if length < MinTokenBytes {
		length = MinTokenBytes
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ValidateEmail validates an email address using net/mail (RFC 5322). The
// literal "admin" is accepted as a special-case username for a bootstrap admin
// account that may not yet have a real email.
func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	if email == "admin" {
		return nil
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email format")
	}
	if addr.Address != email {
		return errors.New("invalid email format: display name not allowed")
	}
	if len(email) > 254 {
		return errors.New("email is too long")
	}
	return nil
}
