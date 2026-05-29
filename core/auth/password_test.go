package auth

import (
	"strings"
	"testing"
)

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword("correct horse battery staple", hash) {
		t.Error("correct password should match")
	}
	if CheckPassword("wrong", hash) {
		t.Error("wrong password should not match")
	}
}

func TestCheckPasswordEmptyHashConstantTime(t *testing.T) {
	// Empty hash must return false (and not panic) — the dummy-hash compare
	// keeps timing comparable to a real miss.
	if CheckPassword("anything", "") {
		t.Error("empty hash should never match")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("correct horse battery staple"); err != nil {
		t.Errorf("strong passphrase should pass: %v", err)
	}
	if err := ValidatePassword("short"); err == nil {
		t.Error("too-short password should fail")
	}
	if err := ValidatePassword("password123"); err == nil {
		t.Error("common password should fail")
	}
	if err := ValidatePassword(strings.Repeat("a", MaxPasswordLength+1)); err == nil {
		t.Error("over-long password should fail")
	}
}

func TestValidatePasswordAggregatesErrors(t *testing.T) {
	err := ValidatePassword("short")
	var pErr *PasswordValidationError
	if !asPasswordErr(err, &pErr) {
		t.Fatalf("expected *PasswordValidationError, got %T", err)
	}
	if len(pErr.Errors) == 0 {
		t.Error("expected at least one violation listed")
	}
}

func asPasswordErr(err error, target **PasswordValidationError) bool {
	if pe, ok := err.(*PasswordValidationError); ok {
		*target = pe
		return true
	}
	return false
}

func TestPasswordStrengthScore(t *testing.T) {
	weak := ValidatePasswordStrength("aaa")
	strong := ValidatePasswordStrength("correct horse battery staple xyzzy")
	if weak >= strong {
		t.Errorf("strong (%d) should score higher than weak (%d)", strong, weak)
	}
	if common := ValidatePasswordStrength("password123"); common > 50 {
		t.Errorf("common password scored %d, expected penalty", common)
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	pw, err := GenerateRandomPassword()
	if err != nil {
		t.Fatalf("GenerateRandomPassword: %v", err)
	}
	if len(pw) != GeneratedPasswordLen {
		t.Errorf("len = %d, want %d", len(pw), GeneratedPasswordLen)
	}
	if err := ValidatePassword(pw); err != nil {
		t.Errorf("generated password should pass policy: %v", err)
	}
}

func TestGetPasswordEntropyAndRequirements(t *testing.T) {
	if GetPasswordEntropy("correct horse battery staple") <= GetPasswordEntropy("aaa") {
		t.Error("longer/varied password should have more entropy")
	}
	if len(GetPasswordRequirements()) == 0 {
		t.Error("requirements list should be non-empty")
	}
}
