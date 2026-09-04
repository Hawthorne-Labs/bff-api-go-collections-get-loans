package usecases

import (
	"context"
	"fmt"
	"strings"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

// allowedSearchBy mirrors the Python BFF Literal allowlist for search_by.
var allowedSearchBy = map[string]struct{}{
	"nombre":    {},
	"id":        {},
	"identidad": {},
	"prestamo":  {},
	"telefono":  {},
	"placa":     {},
	"vin":       {},
}

// loansCore is the Core subset used by LoansUsecase (enables unit tests).
type loansCore interface {
	ListLoans(ctx context.Context, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error)
	GetLoan(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error)
	GetLoanBalance(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error)
	GetLoanInstallments(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error)
	GetLoanStatement(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error)
}

// LoansUsecase handles all loan-related business logic.
type LoansUsecase struct {
	core loansCore
}

// NewLoansUsecase creates a new LoansUsecase.
func NewLoansUsecase(core *coreclient.CoreClient) *LoansUsecase {
	return &LoansUsecase{core: core}
}

// NewLoansUsecaseWithCore creates a LoansUsecase with a testable core stub.
func NewLoansUsecaseWithCore(core loansCore) *LoansUsecase {
	return &LoansUsecase{core: core}
}

// ListParams holds the query parameters for loan listing.
type ListParams struct {
	Search         string
	SearchBy       string
	Status         string
	Sort           string
	AgentID        string
	ClientID       string
	ClientIdentity string
	BranchTenant   string
	BranchName     string
	View           string
	Limit          int
	Offset         int
}

// ListLoans lists loans for the cartera view with pagination and filters.
func (u *LoansUsecase) ListLoans(ctx context.Context, traceID, tenantID, userEmail string, params ListParams) (map[string]any, error) {
	normalizedSearchBy, err := normalizeSearchBy(params.SearchBy)
	if err != nil {
		return nil, err
	}
	params.SearchBy = normalizedSearchBy

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
	// anti-regresion: BUG-1010 — teléfono con espacios/guiones no debe ir crudo al Core.
	if params.SearchBy == "telefono" && params.Search != "" {
		queryParams["search"] = digitsOnly(params.Search)
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
	if params.ClientIdentity != "" {
		queryParams["client_identity"] = params.ClientIdentity
	}
	if params.BranchTenant != "" {
		queryParams["branch_tenant"] = params.BranchTenant
	}
	if params.BranchName != "" {
		queryParams["branch_name"] = params.BranchName
	}
	if params.View != "" {
		queryParams["view"] = params.View
	}

	return u.core.ListLoans(ctx, traceID, tenantID, userEmail, queryParams)
}

func normalizeSearchBy(searchBy string) (string, error) {
	if searchBy == "" {
		return "", nil
	}
	normalized := strings.ToLower(strings.TrimSpace(searchBy))
	if _, ok := allowedSearchBy[normalized]; !ok {
		return "", domain.NewHTTPBusinessError(422, domain.ValidationFailed, "Validacion fallida.")
	}
	return normalized, nil
}

func digitsOnly(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func viewParams(view string) map[string]string {
	if view == "" {
		return nil
	}
	return map[string]string{"view": view}
}

// GetLoanDetail gets complete loan detail with nested client/vehicle/payment promises.
func (u *LoansUsecase) GetLoanDetail(ctx context.Context, loanID, traceID, tenantID, userEmail, view string) (map[string]any, error) {
	return u.core.GetLoan(ctx, loanID, traceID, tenantID, userEmail, viewParams(view))
}

// GetLoanBalance gets loan balance breakdown (capital vencido, intereses, mora).
func (u *LoansUsecase) GetLoanBalance(ctx context.Context, loanID, traceID, tenantID, userEmail, view string) (map[string]any, error) {
	return u.core.GetLoanBalance(ctx, loanID, traceID, tenantID, userEmail, viewParams(view))
}

// GetLoanInstallments gets loan installments plan (amortization schedule, paged).
func (u *LoansUsecase) GetLoanInstallments(ctx context.Context, loanID, traceID, tenantID, userEmail string, limit, offset int, view string) (map[string]any, error) {
	params := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}
	if view != "" {
		params["view"] = view
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
