package usecases

import (
	"net/http"
	"testing"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

func TestValidateAssignmentDistributionTable(t *testing.T) {
	tests := []struct {
		name    string
		body    map[string]any
		wantErr bool
		wantMsg string
	}{
		{
			name: "cuentas_zero",
			body: map[string]any{
				"cuentas":      float64(0),
				"distribucion": []any{map[string]any{"agentId": "a1", "cuentas": float64(1)}},
			},
			wantErr: true,
			wantMsg: "cuentas debe ser mayor a cero",
		},
		{
			name: "distribucion_missing",
			body: map[string]any{
				"cuentas":      float64(1),
				"distribucion": []any{},
			},
			wantErr: true,
			wantMsg: "distribucion es requerida",
		},
		{
			name: "sum_mismatch",
			body: map[string]any{
				"cuentas": float64(5),
				"distribucion": []any{
					map[string]any{"agentId": "a1", "cuentas": float64(2)},
					map[string]any{"agentId": "a2", "cuentas": float64(2)},
				},
			},
			wantErr: true,
			wantMsg: "La suma de distribucion debe coincidir con cuentas",
		},
		{
			name: "row_zero_cuentas",
			body: map[string]any{
				"cuentas": float64(1),
				"distribucion": []any{
					map[string]any{"agentId": "a1", "cuentas": float64(0)},
				},
			},
			wantErr: true,
			wantMsg: "Cada agente en distribucion debe recibir al menos una cuenta",
		},
		{
			name: "ok_match",
			body: map[string]any{
				"cuentas": float64(4),
				"distribucion": []any{
					map[string]any{"agentId": "a1", "cuentas": float64(2)},
					map[string]any{"agentId": "a2", "cuentas": float64(2)},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAssignmentDistribution(tt.body)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				bizErr, ok := err.(*domain.BusinessError)
				if !ok {
					t.Fatalf("expected *domain.BusinessError, got %T", err)
				}
				if bizErr.Code != domain.ValidationFailed {
					t.Errorf("code = %d, want %d", bizErr.Code, domain.ValidationFailed)
				}
				if bizErr.Status() != http.StatusUnprocessableEntity {
					t.Errorf("status = %d, want 422", bizErr.Status())
				}
				if tt.wantMsg != "" && bizErr.Message != tt.wantMsg {
					t.Errorf("message = %q, want %q", bizErr.Message, tt.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
