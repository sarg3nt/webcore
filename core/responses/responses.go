// Package responses provides the generic JSON envelopes shared across webcore
// apps, plus a small helper for writing them.
//
// App-specific response DTOs belong in the app, not here — this package holds
// only the envelopes every app uses: a success wrapper, an error wrapper, and
// a validation-result wrapper.
package responses

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents a standard error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// SuccessResponse represents a standard success response.
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ValidationResult represents the outcome of validating some input.
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ValidationResponse wraps a ValidationResult for transport.
type ValidationResponse struct {
	Result ValidationResult `json:"result"`
}

// WriteJSON writes v as a JSON response with the given status code and the
// application/json content type. It returns any encoding error so callers can
// log it; the status and content-type headers are already committed by then.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
