package errors

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteHTTPError_JSONEnvelope guards the wire format consumers of
// WriteHTTPError rely on — any JS that calls `response.json()` on both success
// and error responses. A `text/plain` body ("Failed to ...") would make
// `JSON.parse` throw on the leading non-JSON character; the envelope keeps the
// success and error shapes parseable the same way.
func TestWriteHTTPError_JSONEnvelope(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := httptest.NewRecorder()

	WriteHTTPError(w, logger, Internal("fetch logs", io.EOF))

	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := w.Code; got != http.StatusInternalServerError {
		t.Fatalf("Status = %d, want 500", got)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v\nbody=%q", err, w.Body.String())
	}
	if body["success"] != false {
		t.Errorf("body.success = %v, want false", body["success"])
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "fetch logs") {
		t.Errorf("body.message = %q, want it to contain 'fetch logs'", msg)
	}
}

// TestWriteHTTPError_UnknownErrorWraps verifies that a plain error (not an
// AppError) still serializes as a JSON envelope with the generic
// "process request" wrapping that Internal() produces.
func TestWriteHTTPError_UnknownErrorWraps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := httptest.NewRecorder()

	WriteHTTPError(w, logger, io.ErrUnexpectedEOF)

	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v\nbody=%q", err, w.Body.String())
	}
	if body["success"] != false {
		t.Errorf("body.success = %v, want false", body["success"])
	}
}

func TestConstructors_StatusCodes(t *testing.T) {
	cases := []struct {
		name string
		err  *AppError
		want int
	}{
		{"NotFound", NotFound("widget", nil), http.StatusNotFound},
		{"Unauthorized", Unauthorized("nope", nil), http.StatusUnauthorized},
		{"Forbidden", Forbidden("nope", nil), http.StatusForbidden},
		{"BadRequest", BadRequest("bad", nil), http.StatusBadRequest},
		{"Internal", Internal("do thing", nil), http.StatusInternalServerError},
		{"ServiceUnavailable", ServiceUnavailable("svc", nil), http.StatusServiceUnavailable},
		{"Conflict", Conflict("dup", nil), http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != tc.want {
				t.Errorf("Code = %d, want %d", tc.err.Code, tc.want)
			}
		})
	}
}

func TestError_UnwrapAndMessage(t *testing.T) {
	inner := io.EOF
	e := Internal("fetch", inner)
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v, want %v", got, inner)
	}
	if !strings.Contains(e.Error(), "EOF") {
		t.Errorf("Error() = %q, want it to wrap the inner error", e.Error())
	}
	noInner := Forbidden("denied", nil)
	if noInner.Error() != "denied" {
		t.Errorf("Error() = %q, want %q", noInner.Error(), "denied")
	}
}

func TestWrapDatabaseError(t *testing.T) {
	if got := WrapDatabaseError(nil, "op"); got != nil {
		t.Errorf("WrapDatabaseError(nil) = %v, want nil", got)
	}
	if got := WrapDatabaseError(sql.ErrNoRows, "op"); got.Code != http.StatusNotFound {
		t.Errorf("ErrNoRows Code = %d, want 404", got.Code)
	}
	if got := WrapDatabaseError(io.EOF, "op"); got.Code != http.StatusInternalServerError {
		t.Errorf("generic Code = %d, want 500", got.Code)
	}
}

func TestIsNotFoundAndIgnore(t *testing.T) {
	if !IsNotFound(sql.ErrNoRows) {
		t.Error("IsNotFound(ErrNoRows) = false, want true")
	}
	if IsNotFound(io.EOF) {
		t.Error("IsNotFound(EOF) = true, want false")
	}
	if got := IgnoreNotFound(sql.ErrNoRows); got != nil {
		t.Errorf("IgnoreNotFound(ErrNoRows) = %v, want nil", got)
	}
	if got := IgnoreNotFound(io.EOF); got != io.EOF {
		t.Errorf("IgnoreNotFound(EOF) = %v, want EOF", got)
	}
}

func TestSanitizeError(t *testing.T) {
	if got := SanitizeError(nil); got != "" {
		t.Errorf("SanitizeError(nil) = %q, want empty", got)
	}
	if got := SanitizeError(BadRequest("bad input", io.EOF)); got != "bad input" {
		t.Errorf("SanitizeError(AppError) = %q, want user message", got)
	}
	if got := SanitizeError(sql.ErrNoRows); got != "Resource not found" {
		t.Errorf("SanitizeError(ErrNoRows) = %q", got)
	}
	if got := SanitizeError(io.EOF); !strings.Contains(got, "error occurred") {
		t.Errorf("SanitizeError(generic) = %q, want generic fallback", got)
	}
}

func TestWithContext(t *testing.T) {
	e := New(http.StatusTeapot, "teapot", nil).WithContext("k", "v")
	if e.LogContext["k"] != "v" {
		t.Errorf("LogContext[k] = %v, want v", e.LogContext["k"])
	}
	// NotFound seeds resource context.
	nf := NotFound("widget", nil)
	if nf.LogContext["resource"] != "widget" {
		t.Errorf("NotFound resource context = %v, want widget", nf.LogContext["resource"])
	}
}

// ensure AppError satisfies the error interface
var _ error = (*AppError)(nil)

func ExampleInternal() {
	e := Internal("save record", io.EOF)
	fmt.Println(e.Code)
	fmt.Println(e.UserMessage)
	// Output:
	// 500
	// Failed to save record. Please try again later.
}
