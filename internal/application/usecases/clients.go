package usecases

import (
	"context"
	"fmt"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

// ClientsUsecase handles all client-related business logic.
type ClientsUsecase struct {
	core *coreclient.CoreClient
}

// NewClientsUsecase creates a new ClientsUsecase.
func NewClientsUsecase(core *coreclient.CoreClient) *ClientsUsecase {
	return &ClientsUsecase{core: core}
}

// ListParams holds the query parameters for client listing.
type ListParams struct {
	Search string
	Limit  int
	Offset int
}

// ListClients lists the client directory with pagination and search.
func (u *ClientsUsecase) ListClients(ctx context.Context, traceID, tenantID, userEmail string, params ListParams) (map[string]any, error) {
	queryParams := map[string]string{
		"limit":  fmt.Sprintf("%d", params.Limit),
		"offset": fmt.Sprintf("%d", params.Offset),
	}
	if params.Search != "" {
		queryParams["search"] = params.Search
	}
	return u.core.ListClients(ctx, traceID, tenantID, userEmail, queryParams)
}

// ListClientContacts gets per-client aggregated contact info.
func (u *ClientsUsecase) ListClientContacts(ctx context.Context, traceID, tenantID, userEmail string, limit, offset int) (map[string]any, error) {
	queryParams := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}
	return u.core.ListClientContacts(ctx, traceID, tenantID, userEmail, queryParams)
}

// ListAtRisk gets unique clients in mora — the strategy assignment pool.
func (u *ClientsUsecase) ListAtRisk(ctx context.Context, traceID, tenantID, userEmail string, limit, offset int) (map[string]any, error) {
	queryParams := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}
	return u.core.ListAtRisk(ctx, traceID, tenantID, userEmail, queryParams)
}
