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

func contextStrings(c *gin.Context) (traceID, tenantID string) {
	if v, ok := c.Get("trace_id"); ok {
		if s, ok := v.(string); ok {
			traceID = s
		}
	}
	// anti-regresion: BUG-1008 Python get_principal_tenant_id always "default" for Core loans/contacts.
	// SPA X-Tenant-Id is the operational marca for FLE only — never forward it as Core tenant.
	tenantID = "default"
	return traceID, tenantID
}


// ListLoans handles GET /api/v1/collections/loans
func (h *LoansHandler) ListLoans(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, tenantID := contextStrings(c)

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	agentID := ""
	if requested := c.Query("agent_id"); requested != "" {
		// anti-regresion: BUG-0945 — agent/call_center cannot spoof another agent_id
		agentID = middleware.ResolveAgentID(ctx, requested)
	}
	params := usecases.ListParams{
		Search:         c.Query("search"),
		SearchBy:       c.Query("search_by"),
		Status:         c.Query("status"),
		Sort:           c.Query("sort"),
		AgentID:        agentID,
		ClientID:       c.Query("client_id"),
		ClientIdentity: c.Query("client_identity"),
		BranchTenant:   c.Query("branch_tenant"),
		BranchName:     c.Query("branch_name"),
		View:           c.Query("view"),
		Limit:          limit,
		Offset:         offset,
	}

	result, err := h.loans.ListLoans(c.Request.Context(), traceID, tenantID, ctx.Email, params)
	if err != nil {
		writeBizError(c, err, domain.LoansListFailed, "No se pudo cargar la cartera de préstamos.")
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLoan handles GET /api/v1/collections/loans/:loanId
func (h *LoansHandler) GetLoan(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, tenantID := contextStrings(c)
	view := c.Query("view")

	result, err := h.loans.GetLoanDetail(c.Request.Context(), loanID, traceID, tenantID, ctx.Email, view)
	if err != nil {
		writeBizError(c, err, domain.LoanDetailLoadFailed, "No se pudo cargar el detalle del préstamo.")
		return
	}

	result = maskClientPII(result)
	c.JSON(http.StatusOK, result)
}

// GetLoanBalance handles GET /api/v1/collections/loans/:loanId/balance
func (h *LoansHandler) GetLoanBalance(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, tenantID := contextStrings(c)
	view := c.Query("view")

	result, err := h.loans.GetLoanBalance(c.Request.Context(), loanID, traceID, tenantID, ctx.Email, view)
	if err != nil {
		writeBizError(c, err, domain.LoanBalanceLoadFailed, "No se pudo cargar el saldo del préstamo.")
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLoanInstallments handles GET /api/v1/collections/loans/:loanId/installments
func (h *LoansHandler) GetLoanInstallments(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, tenantID := contextStrings(c)

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 50
	}
	view := c.Query("view")

	result, err := h.loans.GetLoanInstallments(c.Request.Context(), loanID, traceID, tenantID, ctx.Email, limit, offset, view)
	if err != nil {
		writeBizError(c, err, domain.LoanPaymentPlanLoad, "No se pudo cargar el plan de pago del préstamo.")
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLoanStatement handles GET /api/v1/collections/loans/:loanId/statement
func (h *LoansHandler) GetLoanStatement(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}

	loanID := c.Param("loanId")
	traceID, tenantID := contextStrings(c)

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 50
	}

	result, err := h.loans.GetLoanStatement(c.Request.Context(), loanID, traceID, tenantID, ctx.Email, struct {
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
		writeBizError(c, err, domain.LoanStatementLoad, "No se pudo cargar el estado de cuenta del préstamo.")
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

	result["data"] = data
	data["client"] = maskedClient
	return result
}
