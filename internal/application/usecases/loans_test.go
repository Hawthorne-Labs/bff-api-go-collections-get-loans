package usecases

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

type mockLoansCore struct {
	listCalls         []map[string]string
	getCalls          []map[string]string
	balanceCalls      []map[string]string
	installmentCalls  []map[string]string
	statementCalls    []map[string]string
	listResp          map[string]any
	listErr           error
}

func (m *mockLoansCore) ListLoans(_ context.Context, _, _, _ string, params map[string]string) (map[string]any, error) {
	cp := map[string]string{}
	for k, v := range params {
		cp[k] = v
	}
	m.listCalls = append(m.listCalls, cp)
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listResp != nil {
		return m.listResp, nil
	}
	return map[string]any{"items": []any{}, "total": 0}, nil
}

func (m *mockLoansCore) GetLoan(_ context.Context, _, _, _, _ string, params map[string]string) (map[string]any, error) {
	m.getCalls = append(m.getCalls, copyParams(params))
	return map[string]any{"data": map[string]any{}}, nil
}

func (m *mockLoansCore) GetLoanBalance(_ context.Context, _, _, _, _ string, params map[string]string) (map[string]any, error) {
	m.balanceCalls = append(m.balanceCalls, copyParams(params))
	return map[string]any{"data": map[string]any{}}, nil
}

func (m *mockLoansCore) GetLoanInstallments(_ context.Context, _, _, _, _ string, params map[string]string) (map[string]any, error) {
	m.installmentCalls = append(m.installmentCalls, copyParams(params))
	return map[string]any{"items": []any{}}, nil
}

func (m *mockLoansCore) GetLoanStatement(_ context.Context, _, _, _, _ string, params map[string]string) (map[string]any, error) {
	m.statementCalls = append(m.statementCalls, copyParams(params))
	return map[string]any{"items": []any{}}, nil
}

func copyParams(params map[string]string) map[string]string {
	if params == nil {
		return nil
	}
	cp := map[string]string{}
	for k, v := range params {
		cp[k] = v
	}
	return cp
}

func TestListLoansForwardsTelefonoWithEveryStatus(t *testing.T) {
	for _, status := range []string{"", "mora", "legal", "vigente"} {
		t.Run("status_"+status, func(t *testing.T) {
			mock := &mockLoansCore{}
			uc := NewLoansUsecaseWithCore(mock)
			_, err := uc.ListLoans(context.Background(), "t", "default", "a@t.local", ListParams{
				Search:   "+504 9479-4882",
				SearchBy: "telefono",
				Status:   status,
				View:     "search",
				Limit:    20,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := mock.listCalls[0]
			if got["search"] != "50494794882" || got["search_by"] != "telefono" {
				t.Fatalf("phone not forwarded: %#v", got)
			}
			if status == "" {
				if _, ok := got["status"]; ok {
					t.Fatalf("todos must omit status: %#v", got)
				}
			} else if got["status"] != status {
				t.Fatalf("status=%q want %q in %#v", got["status"], status, got)
			}
		})
	}
}

func TestListLoansStripsPhoneFormatting(t *testing.T) {
	mock := &mockLoansCore{}
	uc := NewLoansUsecaseWithCore(mock)
	_, err := uc.ListLoans(context.Background(), "t", "default", "a@t.local", ListParams{
		Search: "+504 9479-4882", SearchBy: "telefono", View: "search", Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mock.listCalls[0]["search"] != "50494794882" {
		t.Fatalf("search=%q", mock.listCalls[0]["search"])
	}
}

func TestListLoansForwardsTelefonoSearchBy(t *testing.T) {
	// anti-regresion: BUG-1002 — search_by=telefono must reach Core
	mock := &mockLoansCore{}
	uc := NewLoansUsecaseWithCore(mock)

	_, err := uc.ListLoans(context.Background(), "trace-1", "default", "agent@test.local", ListParams{
		Search:   "9999-1234",
		SearchBy: "telefono",
		View:     "search",
		Limit:    20,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("ListLoans returned error: %v", err)
	}
	if len(mock.listCalls) != 1 {
		t.Fatalf("expected 1 core call, got %d", len(mock.listCalls))
	}
	got := mock.listCalls[0]
	// anti-regresion: BUG-1010 — BFF envía solo dígitos al Core para telefono.
	if got["search"] != "99991234" {
		t.Errorf("search = %q, want %q", got["search"], "99991234")
	}
	if got["search_by"] != "telefono" {
		t.Errorf("search_by = %q, want %q", got["search_by"], "telefono")
	}
	if got["view"] != "search" {
		t.Errorf("view = %q, want %q", got["view"], "search")
	}
}

func TestListLoansSearchByAllowlist(t *testing.T) {
	allowed := []string{"nombre", "id", "identidad", "prestamo", "telefono", "placa", "vin", "TELEFONO", " Nombre "}
	for _, field := range allowed {
		t.Run("accept_"+field, func(t *testing.T) {
			mock := &mockLoansCore{}
			uc := NewLoansUsecaseWithCore(mock)
			_, err := uc.ListLoans(context.Background(), "t", "default", "a@t.local", ListParams{
				Search: "x", SearchBy: field, Limit: 20,
			})
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", field, err)
			}
			if mock.listCalls[0]["search_by"] == "" {
				t.Fatal("expected normalized search_by forwarded")
			}
		})
	}

	t.Run("reject_unknown", func(t *testing.T) {
		mock := &mockLoansCore{}
		uc := NewLoansUsecaseWithCore(mock)
		_, err := uc.ListLoans(context.Background(), "t", "default", "a@t.local", ListParams{
			Search: "value", SearchBy: "raw_sql", Limit: 20,
		})
		if err == nil {
			t.Fatal("expected validation error")
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
		if len(mock.listCalls) != 0 {
			t.Errorf("expected no core calls, got %d", len(mock.listCalls))
		}
	})
}

func TestListLoansForwardsClientIdentityAndView(t *testing.T) {
	mock := &mockLoansCore{}
	uc := NewLoansUsecaseWithCore(mock)

	_, err := uc.ListLoans(context.Background(), "trace-1", "default", "agent@test.local", ListParams{
		ClientIdentity: "0801-1990-12345",
		View:           "search",
		Limit:          500,
		Offset:         0,
	})
	if err != nil {
		t.Fatalf("ListLoans returned error: %v", err)
	}
	got := mock.listCalls[0]
	if got["client_identity"] != "0801-1990-12345" {
		t.Errorf("client_identity = %q", got["client_identity"])
	}
	if got["view"] != "search" {
		t.Errorf("view = %q", got["view"])
	}
}

func TestLoanDetailPathsForwardSearchView(t *testing.T) {
	mock := &mockLoansCore{}
	uc := NewLoansUsecaseWithCore(mock)
	ctx := context.Background()

	if _, err := uc.GetLoanDetail(ctx, "loan-1", "t", "default", "a@t.local", "search"); err != nil {
		t.Fatalf("GetLoanDetail: %v", err)
	}
	if _, err := uc.GetLoanBalance(ctx, "loan-1", "t", "default", "a@t.local", "search"); err != nil {
		t.Fatalf("GetLoanBalance: %v", err)
	}
	if _, err := uc.GetLoanInstallments(ctx, "loan-1", "t", "default", "a@t.local", 50, 0, "search"); err != nil {
		t.Fatalf("GetLoanInstallments: %v", err)
	}
	if _, err := uc.GetLoanStatement(ctx, "loan-1", "t", "default", "a@t.local", struct {
		FromDate string
		ToDate   string
		Limit    int
		Offset   int
		View     string
	}{Limit: 50, View: "search"}); err != nil {
		t.Fatalf("GetLoanStatement: %v", err)
	}

	for name, calls := range map[string][]map[string]string{
		"get":         mock.getCalls,
		"balance":     mock.balanceCalls,
		"installments": mock.installmentCalls,
		"statement":   mock.statementCalls,
	} {
		if len(calls) != 1 {
			t.Fatalf("%s: expected 1 call, got %d", name, len(calls))
		}
		if calls[0]["view"] != "search" {
			t.Errorf("%s view = %q, want search", name, calls[0]["view"])
		}
	}
}

func TestListLoansRejectsUnknownSearchBy(t *testing.T) {
	mock := &mockLoansCore{}
	uc := NewLoansUsecaseWithCore(mock)

	_, err := uc.ListLoans(context.Background(), "trace-1", "default", "agent@test.local", ListParams{
		Search:   "value",
		SearchBy: "raw_sql",
		Limit:    20,
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !errors.As(err, new(*domain.BusinessError)) {
		t.Fatalf("expected *domain.BusinessError, got %T", err)
	}
}
