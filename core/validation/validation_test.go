package validation

import "testing"

func TestRequired(t *testing.T) {
	if Required("f", "x") != nil {
		t.Error("non-empty should pass")
	}
	if Required("f", "   ") == nil {
		t.Error("whitespace-only should fail")
	}
}

func TestMinMaxLength(t *testing.T) {
	if MinLength("f", "ab", 3) == nil {
		t.Error("too short should fail")
	}
	if MinLength("f", "abc", 3) != nil {
		t.Error("exact min should pass")
	}
	if MaxLength("f", "abcd", 3) == nil {
		t.Error("too long should fail")
	}
	if MaxLength("f", "abc", 3) != nil {
		t.Error("exact max should pass")
	}
}

func TestEmail(t *testing.T) {
	if Email("f", "") != nil {
		t.Error("empty email defers to Required")
	}
	if Email("f", "dave@sarg3.net") != nil {
		t.Error("valid email should pass")
	}
	if Email("f", "not-an-email") == nil {
		t.Error("invalid email should fail")
	}
}

func TestURL(t *testing.T) {
	if URL("f", "https://example.com/x") != nil {
		t.Error("valid URL should pass")
	}
	if URL("f", "://nope") == nil {
		t.Error("invalid URL should fail")
	}
}

func TestAlphanumeric(t *testing.T) {
	if Alphanumeric("f", "abc-DEF_123") != nil {
		t.Error("valid token should pass")
	}
	if Alphanumeric("f", "has space") == nil {
		t.Error("space should fail")
	}
}

func TestIP(t *testing.T) {
	if IP("f", "10.0.0.1") != nil {
		t.Error("valid IP should pass")
	}
	if IP("f", "256.1.1.1") == nil {
		t.Error("octet > 255 should fail")
	}
	if IP("f", "1.2.3") == nil {
		t.Error("too few octets should fail")
	}
}

func TestPort(t *testing.T) {
	if Port("f", "8080") != nil {
		t.Error("valid port should pass")
	}
	if Port("f", "0") == nil {
		t.Error("port 0 should fail")
	}
	if Port("f", "70000") == nil {
		t.Error("port > 65535 should fail")
	}
}

func TestHostname(t *testing.T) {
	if Hostname("f", "host.example.com") != nil {
		t.Error("valid hostname should pass")
	}
	if Hostname("f", "-bad.com") == nil {
		t.Error("leading hyphen should fail")
	}
}

func TestInRange(t *testing.T) {
	if InRange("f", 5, 1, 10) != nil {
		t.Error("in range should pass")
	}
	if InRange("f", 11, 1, 10) == nil {
		t.Error("out of range should fail")
	}
}

func TestOneOf(t *testing.T) {
	allowed := []string{"a", "b"}
	if OneOf("f", "a", allowed) != nil {
		t.Error("member should pass")
	}
	if OneOf("f", "c", allowed) == nil {
		t.Error("non-member should fail")
	}
}

func TestPasswordStrength(t *testing.T) {
	if PasswordStrength("f", "Abcdef12") != nil {
		t.Error("strong password should pass")
	}
	if PasswordStrength("f", "short1A") == nil {
		t.Error("too short should fail")
	}
	if PasswordStrength("f", "alllowercase1") == nil {
		t.Error("no uppercase should fail")
	}
}

func TestNoSQLInjectionAndXSS(t *testing.T) {
	if NoSQLInjection("f", "normal value") != nil {
		t.Error("clean value should pass")
	}
	if NoSQLInjection("f", "1; DROP TABLE users") == nil {
		t.Error("sql payload should fail")
	}
	if NoXSS("f", "hello") != nil {
		t.Error("clean value should pass")
	}
	if NoXSS("f", "<script>alert(1)</script>") == nil {
		t.Error("xss payload should fail")
	}
}

func TestValidateChainStopsAtFirst(t *testing.T) {
	err := Validate("username", "",
		func(v string) error { return Required("username", v) },
		func(v string) error { return MinLength("username", v, 3) },
	)
	if err == nil || err.Field != "username" {
		t.Fatalf("expected Required error, got %v", err)
	}
	if err.Message != "is required" {
		t.Errorf("first failing validator should win, got %q", err.Message)
	}
}

func TestValidateAllCollects(t *testing.T) {
	validations := map[string][]Validator{
		"email": {
			func(v string) error { return Required("email", v) },
			func(v string) error { return Email("email", v) },
		},
	}
	values := map[string]string{"email": ""}
	errs := ValidateAll(validations, values)
	if !errs.HasErrors() {
		t.Fatal("expected errors for empty required email")
	}
	if errs.Error() == "" {
		t.Error("Error() should join messages")
	}
}
