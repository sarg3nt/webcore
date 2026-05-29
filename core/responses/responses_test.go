package responses

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	if err := WriteJSON(w, http.StatusCreated, SuccessResponse{Success: true, Message: "done"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var got SuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if !got.Success || got.Message != "done" {
		t.Errorf("round-trip = %+v", got)
	}
}

func TestEnvelopesOmitEmpty(t *testing.T) {
	b, _ := json.Marshal(ErrorResponse{Error: "boom"})
	if strings.Contains(string(b), "code") || strings.Contains(string(b), "details") {
		t.Errorf("empty optional fields should be omitted: %s", b)
	}
	b, _ = json.Marshal(ValidationResponse{Result: ValidationResult{Valid: true}})
	if strings.Contains(string(b), "errors") || strings.Contains(string(b), "warnings") {
		t.Errorf("empty slices should be omitted: %s", b)
	}
}
