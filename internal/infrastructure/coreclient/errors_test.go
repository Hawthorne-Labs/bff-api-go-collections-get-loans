package coreclient

import (
	"net/http"
	"testing"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

func TestTranslateCoreErrorConflictPreservesHttpStatus(t *testing.T) {
	body := []byte(`{"error_code":"ROLE_EXISTS","message":"Ya existe un rol con ese código."}`)
	err := translateCoreError(http.StatusConflict, body)
	if err.Status() != http.StatusConflict {
		t.Fatalf("status=%d want %d", err.Status(), http.StatusConflict)
	}
	if err.Code != domain.RoleMutationFailed {
		t.Fatalf("code=%d want %d", err.Code, domain.RoleMutationFailed)
	}
	if err.Message != "Ya existe un rol con ese código." {
		t.Fatalf("message=%q", err.Message)
	}
}
