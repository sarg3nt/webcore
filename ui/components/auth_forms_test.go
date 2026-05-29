package components

import (
	"strings"
	"testing"
)

func TestLoginForm(t *testing.T) {
	got := render(t, LoginForm(LoginFormData{
		Action: "/login", CSRFToken: "tok123", ReturnURL: "/dash",
		Error: "bad creds", ShowWebAuthn: true,
	}))
	checks := []string{
		`action="/login"`,
		`name="csrf_token" value="tok123"`,
		`name="return" value="/dash"`,
		"bad creds",
		`name="email"`,
		`name="password"`,
		"webauthn-login-btn",
	}
	for _, c := range checks {
		if !strings.Contains(got, c) {
			t.Errorf("LoginForm missing %q in %q", c, got)
		}
	}
}

func TestLoginFormDefaultsAndOmits(t *testing.T) {
	got := render(t, LoginForm(LoginFormData{Action: "/login"}))
	if strings.Contains(got, "csrf_token") {
		t.Error("no CSRF field when token empty")
	}
	if strings.Contains(got, `name="return"`) {
		t.Error("no return field when ReturnURL empty")
	}
	if strings.Contains(got, "webauthn-login-btn") {
		t.Error("no passkey button when ShowWebAuthn false")
	}
	// Default email label.
	if !strings.Contains(got, "Email") {
		t.Errorf("default Email label missing: %q", got)
	}
}

func TestLoginFormCustomEmailLabel(t *testing.T) {
	got := render(t, LoginForm(LoginFormData{Action: "/login", EmailLabel: "Username", EmailValue: "dave"}))
	if !strings.Contains(got, "Username") || !strings.Contains(got, `value="dave"`) {
		t.Errorf("custom label/value: %q", got)
	}
}

func TestChangePasswordForm(t *testing.T) {
	withCur := render(t, ChangePasswordForm(ChangePasswordFormData{Action: "/pw", RequireCurrent: true}))
	if !strings.Contains(withCur, `name="current_password"`) {
		t.Error("RequireCurrent should render current_password field")
	}
	if !strings.Contains(withCur, `name="new_password"`) || !strings.Contains(withCur, `name="confirm_password"`) {
		t.Error("missing new/confirm fields")
	}
	forced := render(t, ChangePasswordForm(ChangePasswordFormData{Action: "/pw", RequireCurrent: false}))
	if strings.Contains(forced, `name="current_password"`) {
		t.Error("forced setup should omit current_password")
	}
}

func TestForgotPasswordForm(t *testing.T) {
	form := render(t, ForgotPasswordForm(ForgotPasswordFormData{Action: "/forgot"}))
	if !strings.Contains(form, `name="email"`) {
		t.Errorf("forgot form should have email: %q", form)
	}
	sent := render(t, ForgotPasswordForm(ForgotPasswordFormData{Sent: true}))
	if strings.Contains(sent, "<form") {
		t.Error("Sent state should not render the form")
	}
	if !strings.Contains(sent, "reset link has been sent") {
		t.Errorf("Sent state should show generic confirmation: %q", sent)
	}
}

func TestResetPasswordForm(t *testing.T) {
	got := render(t, ResetPasswordForm(ResetPasswordFormData{Action: "/reset", Token: "rtok"}))
	if !strings.Contains(got, `name="token" value="rtok"`) {
		t.Errorf("reset form should carry token: %q", got)
	}
	if !strings.Contains(got, `name="new_password"`) || !strings.Contains(got, `name="confirm_password"`) {
		t.Error("reset form missing password fields")
	}
}
