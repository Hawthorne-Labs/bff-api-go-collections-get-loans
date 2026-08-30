package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

type handlerMockCore struct {
	listCalls []map[string]string
	getCalls  []map[string]string
}

func (m *handlerMockCore) ListLoans(_ context.Context, _, _, _ string, params map[string]string) (map[string]any, error) {
	cp := map[string]string{}
	for k, v := range params {
		cp[k] = v
	}
	m.listCalls = append(m.listCalls, cp)
	return map[string]any{"items": []any{}, "total": 0}, nil
}

func (m *handlerMockCore) GetLoan(_ context.Context, _, _, _, _ string, params map[string]string) (map[string]any, error) {
	cp := map[string]string{}
	for k, v := range params {
		cp[k] = v
	}
	m.getCalls = append(m.getCalls, cp)
	return map[string]any{"data": map[string]any{"loan_id": "loan-1", "client": map[string]any{}}}, nil
}

func (m *handlerMockCore) GetLoanBalance(context.Context, string, string, string, string, map[string]string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (m *handlerMockCore) GetLoanInstallments(context.Context, string, string, string, string, map[string]string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (m *handlerMockCore) GetLoanStatement(context.Context, string, string, string, string, map[string]string) (map[string]any, error) {
	return map[string]any{}, nil
}

func withAuth(role, sub string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("cognito_context", &middleware.CognitoContext{
			Sub:   sub,
			Role:  role,
			Scope: "collections:read",
			Email: role + "@test.local",
		})
		c.Set("trace_id", "trace-test")
		c.Set("tenant_id", "default")
		c.Next()
	}
}

func TestListLoansHandlerRejectsUnknownSearchByWith422(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock := &handlerMockCore{}
	h := NewLoansHandler(usecases.NewLoansUsecaseWithCore(mock))

	r := gin.New()
	r.Use(withAuth("agent", "sub-agent"))
	r.GET("/api/v1/collections/loans", h.ListLoans)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collections/loans?search=x&search_by=raw_sql", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	errObj := body["error"].(map[string]any)
	if int(errObj["code"].(float64)) != domain.ValidationFailed {
		t.Errorf("code = %v, want %d", errObj["code"], domain.ValidationFailed)
	}
	if len(mock.listCalls) != 0 {
		t.Errorf("expected no core calls")
	}
}

func TestListLoansHandlerForwardsClientIdentityAndCallCenterAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock := &handlerMockCore{}
	h := NewLoansHandler(usecases.NewLoansUsecaseWithCore(mock))

	r := gin.New()
	r.Use(withAuth("call_center", "sub-cc"))
	r.GET("/api/v1/collections/loans", h.ListLoans)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collections/loans?client_identity=0801-1990-12345&view=search&agent_id=spoofed&limit=20", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", w.Code, w.Body.String())
	}
	got := mock.listCalls[0]
	if got["client_identity"] != "0801-1990-12345" {
		t.Errorf("client_identity = %q", got["client_identity"])
	}
	if got["view"] != "search" {
		t.Errorf("view = %q", got["view"])
	}
	if got["agent_id"] != "sub-cc" {
		t.Errorf("agent_id = %q, want sub-cc (ResolveAgentID)", got["agent_id"])
	}
}

func TestGetLoanHandlerForwardsSearchView(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock := &handlerMockCore{}
	h := NewLoansHandler(usecases.NewLoansUsecaseWithCore(mock))

	r := gin.New()
	r.Use(withAuth("agent", "sub-agent"))
	r.GET("/api/v1/collections/loans/:loanId", h.GetLoan)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collections/loans/loan-123?view=search", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if mock.getCalls[0]["view"] != "search" {
		t.Errorf("view = %q", mock.getCalls[0]["view"])
	}
}
