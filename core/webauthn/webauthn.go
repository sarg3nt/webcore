// Package webauthn is a thin relying-party wrapper over go-webauthn, plus a
// ready-made User adapter so apps don't reimplement the webauthn.User
// interface. Apps keep their own credential persistence (loading/saving rows);
// webcore only owns the RP config and the User shape passed into the library's
// Begin/Finish ceremonies.
package webauthn

import (
	"encoding/binary"
	"fmt"
	"net/url"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// RP wraps a configured go-webauthn relying party.
type RP struct {
	lib *gowebauthn.WebAuthn
}

// Config configures the relying party.
type Config struct {
	// DisplayName is the human-facing RP name shown by authenticators.
	DisplayName string
	// BaseURL is the full origin (scheme://host[:port]) the app is served from.
	BaseURL string
	// RPID overrides the relying-party ID; defaults to BaseURL's hostname.
	RPID string
}

// New builds a relying party from cfg. RPID defaults to the host component of
// BaseURL when empty.
func New(cfg Config) (*RP, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	rpID := cfg.RPID
	if rpID == "" {
		rpID = u.Hostname()
	}
	lib, err := gowebauthn.New(&gowebauthn.Config{
		RPDisplayName: cfg.DisplayName,
		RPID:          rpID,
		RPOrigins:     []string{cfg.BaseURL},
	})
	if err != nil {
		return nil, err
	}
	return &RP{lib: lib}, nil
}

// Lib returns the underlying *webauthn.WebAuthn for the Begin/Finish ceremony
// calls (BeginRegistration, FinishLogin, …).
func (r *RP) Lib() *gowebauthn.WebAuthn { return r.lib }

// User adapts a user + their credentials to the go-webauthn webauthn.User
// interface. Apps populate it from their own storage and pass it into the
// library; the numeric ID is an opaque handle round-tripped as 8 big-endian
// bytes.
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Credentials []gowebauthn.Credential
}

// WebAuthnID returns the user's ID as 8 big-endian bytes (opaque to WebAuthn).
func (u User) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, u.ID)
	return b
}

// WebAuthnName returns the username.
func (u User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the display name, falling back to the username.
func (u User) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Name
}

// WebAuthnCredentials returns the user's registered credentials.
func (u User) WebAuthnCredentials() []gowebauthn.Credential { return u.Credentials }

// WebAuthnIcon is deprecated in the spec; returns "".
func (u User) WebAuthnIcon() string { return "" }
