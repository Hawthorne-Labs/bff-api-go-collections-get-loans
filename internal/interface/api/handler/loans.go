package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// LoansHandler handles all loan-related HTTP endpoints.
type LoansHandler struct {
	loans *usecases.LoansUsecase
}

// NewLoansHandler creates a new LoansHandler.
func NewLoansHandler(loans *usecases.LoansUsecase) *LoansHandler {
	return &LoansHandler{loans: loans}
}

// ListLoans handles GET /api/v1/collections/loans
func (h *LoansHandler) ListLoans(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	params := usecases.ListParams{
		Search:       c.Query("search"),
		SearchBy:     c.Query("search_by"),
		Status:       c.Query("status"),
		Sort:         c.Query("sort"),
		AgentID:      c.Query("agent_id"),
		ClientID:     c.Query("client_id"),
		BranchTenant: c.Query("branch_tenant"),
		View:         c.Query("view"),
		Limit:        limit,
		Offset:       offset,
	}

	result, err := h.loans.ListLoans(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, params)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.LoansListFailed, "message": "No se pudo cargar la cartera de préstamos."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLoan handles GET /api/v1/collections/loans/:loanId
func (h *LoansHandler) GetLoan(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	result, err := h.loans.GetLoanDetail(c.Request.Context(), loanID, traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.LoanDetailLoadFailed, "message": "No se pudo cargar el detalle del préstamo."}})
		return
	}

	// Apply PII masking to client sub-object
	result = maskClientPII(result)

	c.JSON(http.StatusOK, result)
}

// GetLoanBalance handles GET /api/v1/collections/loans/:loanId/balance
func (h *LoansHandler) GetLoanBalance(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	result, err := h.loans.GetLoanBalance(c.Request.Context(), loanID, traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.LoanBalanceLoadFailed, "message": "No se pudo cargar el saldo del préstamo."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLoanInstallments handles GET /api/v1/collections/loans/:loanId/installments
func (h *LoansHandler) GetLoanInstallments(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 50
	}

	result, err := h.loans.GetLoanInstallments(c.Request.Context(), loanID, traceID.(string), tenantID.(string), ctx.Email, limit, offset)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.LoanPaymentPlanLoad, "message": "No se pudo cargar el plan de pago del préstamo."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLoanStatement handles GET /api/v1/collections/loans/:loanId/statement
func (h *LoansHandler) GetLoanStatement(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 50
	}

	result, err := h.loans.GetLoanStatement(c.Request.Context(), loanID, traceID.(string), tenantID.(string), ctx.Email, struct {
		FromDate string
		ToDate   string
		Limit    int
		Offset   int
		View     string
	}{
		FromDate: c.Query("from_date"),
		ToDate:   c.Query("to_date"),
		Limit:    limit,
		Offset:   offset,
		View:     c.Query("view"),
	})
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.LoanStatementLoad, "message": "No se pudo cargar el estado de cuenta del préstamo."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// maskClientPII applies PII masking to the client sub-object in a loan response.
func maskClientPII(result map[string]any) map[string]any {
	data, ok := result["data"].(map[string]any)
	if !ok {
		return result
	}
	client, ok := data["client"].(map[string]any)
	if !ok {
		return result
	}

	maskedClient := map[string]any{}
	for k, v := range client {
		maskedClient[k] = v
	}

	if email, ok := client["email"].(string); ok {
		maskedClient["email"] = domain.MaskEmail(&email)
	}
	if phone, ok := client["phone"].(string); ok {
		maskedClient["phone"] = domain.MaskPhone(&phone)
	}
	if secondaryPhones, ok := client["secondary_phones"].([]any); ok {
		maskedPhones := make([]any, 0, len(secondaryPhones))
		for _, sp := range secondaryPhones {
			if s, ok := sp.(string); ok {
				masked := domain.MaskPhone(&s)
				if masked != nil {
					maskedPhones = append(maskedPhones, *masked)
				}
			}
		}
		maskedClient["secondary_phones"] = maskedPhones
	}

	result["data"] = map[string]any{
		"client":              maskedClient,
		"loan_id":             data["loan_id"],
		"status":              data["status"],
		"principal":           data["principal"],
		"outstanding_balance": data["outstanding_balance"],
		"interest_rate":       data["interest_rate"],
		"vehicle":             data["vehicle"],
		"payment_promises":    data["payment_promises"],
	}
	return result
}
