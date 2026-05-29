// Package auth provides authentication primitives for web-core apps: password
// hashing and policy, secure token / UUID generation, email validation, a
// DB-backed session Manager (driven by the UserStore and AuthUser interfaces),
// request middleware, and the dev-mode loopback auto-login bypass.
//
// core/auth is authentication only. Authorization / RBAC (roles, permissions)
// is intentionally left to the consuming app, which can layer it over the
// authenticated user this package exposes via the request context.
package auth

import (
	"crypto/rand"
	"fmt"
	"strings"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
)

// Password policy constants.
const (
	// MinEntropyBits is the minimum password entropy. 50 bits balances
	// security and usability: a 4-word passphrase scores ~66 bits, a 12-char
	// complex password ~50, and "password123" ~28 (rejected).
	MinEntropyBits = 50
	// MinPasswordLength is the absolute minimum length (NIST recommends 8).
	MinPasswordLength = 8
	// MaxPasswordLength prevents DoS via bcrypt's input handling.
	MaxPasswordLength = 128
	// BcryptCost is the bcrypt hashing cost.
	BcryptCost = 12
	// GeneratedPasswordLen is the length of auto-generated passwords.
	GeneratedPasswordLen = 24
)

// commonPasswords are rejected regardless of entropy — they can score okay on
// length alone but are still bad choices.
var commonPasswords = map[string]bool{
	"password":     true,
	"password123":  true,
	"password1234": true,
	"123456789012": true,
	"qwertyuiop":   true,
	"qwerty123456": true,
	"admin123456":  true,
	"letmein12345": true,
	"welcome12345": true,
	"changeme1234": true,
	"iloveyou1234": true,
	"trustno1234":  true,
}

// PasswordValidationError aggregates password policy violations.
type PasswordValidationError struct {
	Errors []string
}

func (e *PasswordValidationError) Error() string {
	return "password validation failed: " + strings.Join(e.Errors, "; ")
}

// ValidatePassword checks a password against the policy (length bounds, common
// blocklist, entropy). Entropy-based validation supports both passwords and
// passphrases. Returns a *PasswordValidationError listing all violations.
func ValidatePassword(password string) error {
	var errs []string

	if len(password) < MinPasswordLength {
		errs = append(errs, fmt.Sprintf("password must be at least %d characters long", MinPasswordLength))
	}
	if len(password) > MaxPasswordLength {
		errs = append(errs, fmt.Sprintf("password must be no more than %d characters long", MaxPasswordLength))
	}
	if commonPasswords[strings.ToLower(password)] {
		errs = append(errs, "password is too common")
	}
	if err := passwordvalidator.Validate(password, MinEntropyBits); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return &PasswordValidationError{Errors: errs}
	}
	return nil
}

// GetPasswordEntropy returns the entropy score for a password (higher = better;
// 50+ bits is considered secure).
func GetPasswordEntropy(password string) float64 {
	return passwordvalidator.GetEntropy(password)
}

// ValidatePasswordStrength returns a 0-100 strength score derived from entropy,
// penalized for common passwords.
func ValidatePasswordStrength(password string) int {
	entropy := passwordvalidator.GetEntropy(password)

	var score int
	switch {
	case entropy < 30:
		score = int(entropy)
	case entropy < 50:
		score = 30 + int((entropy-30)*1.5)
	case entropy < 70:
		score = 60 + int(entropy-50)
	default:
		score = 80 + int((entropy-70)*0.5)
	}
	if commonPasswords[strings.ToLower(password)] {
		score -= 50
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// dummyHash is a bcrypt hash used to keep CheckPassword's duration roughly
// constant when the stored hash is empty/malformed, preventing a timing oracle
// on the login codepath (does this email exist?). It is the bcrypt of an
// arbitrary string at BcryptCost; the plaintext is never used.
const dummyHash = "$2a$12$KIXIVQwOzpEKW.NHE6.kSeWLi6cm7Trky1H21D9KvCi9TKfRsT4xK"

// HashPassword creates a bcrypt hash of the password. It does NOT validate the
// password policy — call ValidatePassword first where appropriate.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword reports whether password matches hash. When hash is empty it
// still runs a bcrypt comparison against a dummy hash so a missing user and a
// wrong password take comparable time.
func CheckPassword(password, hash string) bool {
	if hash == "" {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// GenerateRandomPassword generates a secure random password that passes
// ValidatePassword.
func GenerateRandomPassword() (string, error) {
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"

	b := make([]byte, GeneratedPasswordLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	password := string(b)
	if err := ValidatePassword(password); err != nil {
		// Extremely unlikely at this length/charset; retry.
		return GenerateRandomPassword()
	}
	return password, nil
}

// GetPasswordRequirements returns a human-readable list of password rules.
func GetPasswordRequirements() []string {
	return []string{
		"At least 8 characters long",
		"Strong enough to resist guessing attacks (use length or variety)",
		"Cannot be a commonly used password",
		"Passphrases like \"correct horse battery staple\" are encouraged",
	}
}
