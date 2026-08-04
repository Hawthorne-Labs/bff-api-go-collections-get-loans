package usecases

import (
	"context"
	"fmt"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

// LoansUsecase handles all loan-related business logic.
type LoansUsecase struct {
	core *coreclient.CoreClient
}

// NewLoansUsecase creates a new LoansUsecase.
func NewLoansUsecase(core *coreclient.CoreClient) *LoansUsecase {
	return &LoansUsecase{core: core}
}

// ListParams holds the query parameters for loan listing.
type ListParams struct {
	Search       string
	SearchBy     string
	Status       string
	Sort         string
	AgentID      string
	ClientID     string
	BranchTenant string
	View         string
	Limit        int
	Offset       int
}

// ListLoans lists loans for the cartera view with pagination and filters.
func (u *LoansUsecase) ListLoans(ctx context.Context, traceID, tenantID, userEmail string, params ListParams) (map[string]any, error) {
	queryParams := map[string]string{
		"limit":  fmt.Sprintf("%d", params.Limit),
		"offset": fmt.Sprintf("%d", params.Offset),
	}
	if params.Search != "" {
		queryParams["search"] = params.Search
	}
	if params.SearchBy != "" {
		queryParams["search_by"] = params.SearchBy
	}
	if params.Status != "" {
		queryParams["status"] = params.Status
	}
	if params.Sort != "" {
		queryParams["sort"] = params.Sort
	}
	if params.AgentID != "" {
		queryParams["agent_id"] = params.AgentID
	}
	if params.ClientID != "" {
		queryParams["client_id"] = params.ClientID
	}
	if params.BranchTenant != "" {
		queryParams["branch_tenant"] = params.BranchTenant
	}
	if params.View != "" {
		queryParams["view"] = params.View
	}

	return u.core.ListLoans(ctx, traceID, tenantID, userEmail, queryParams)
}

// GetLoanDetail gets complete loan detail with nested client/vehicle/payment promises.
func (u *LoansUsecase) GetLoanDetail(ctx context.Context, loanID, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.GetLoan(ctx, loanID, traceID, tenantID, userEmail)
}

// GetLoanBalance gets loan balance breakdown (capital vencido, intereses, mora).
func (u *LoansUsecase) GetLoanBalance(ctx context.Context, loanID, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.GetLoanBalance(ctx, loanID, traceID, tenantID, userEmail)
}

// GetLoanInstallments gets loan installments plan (amortization schedule, paged).
func (u *LoansUsecase) GetLoanInstallments(ctx context.Context, loanID, traceID, tenantID, userEmail string, limit, offset int) (map[string]any, error) {
	params := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}
	return u.core.GetLoanInstallments(ctx, loanID, traceID, tenantID, userEmail, params)
}

// GetLoanStatement gets loan statement/history (account activity, paged, date-filtered).
func (u *LoansUsecase) GetLoanStatement(ctx context.Context, loanID, traceID, tenantID, userEmail string, params struct {
	FromDate string
	ToDate   string
	Limit    int
	Offset   int
	View     string
}) (map[string]any, error) {
	queryParams := map[string]string{
		"limit":  fmt.Sprintf("%d", params.Limit),
		"offset": fmt.Sprintf("%d", params.Offset),
	}
	if params.FromDate != "" {
		queryParams["from_date"] = params.FromDate
	}
	if params.ToDate != "" {
		queryParams["to_date"] = params.ToDate
	}
	if params.View != "" {
		queryParams["view"] = params.View
	}
	return u.core.GetLoanStatement(ctx, loanID, traceID, tenantID, userEmail, queryParams)
}
