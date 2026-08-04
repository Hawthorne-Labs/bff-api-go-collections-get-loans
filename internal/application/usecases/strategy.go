package usecases

import (
	"context"
	"fmt"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

// StrategyUsecase handles all strategy/segmentation business logic.
type StrategyUsecase struct {
	core *coreclient.CoreClient
}

// NewStrategyUsecase creates a new StrategyUsecase.
func NewStrategyUsecase(core *coreclient.CoreClient) *StrategyUsecase {
	return &StrategyUsecase{core: core}
}

// GetSegmentation gets live account counts per priority bucket by marca.
func (u *StrategyUsecase) GetSegmentation(ctx context.Context, traceID, tenantID, userEmail, marca string) (map[string]any, error) {
	return u.core.GetStrategySegmentation(ctx, traceID, tenantID, userEmail, marca)
}

// ListAssignments gets strategy assignment audit trail.
func (u *StrategyUsecase) ListAssignments(ctx context.Context, traceID, tenantID, userEmail string, limit, offset int, marca string) (map[string]any, error) {
	params := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}
	if marca != "" {
		params["marca"] = marca
	}
	return u.core.ListStrategyAssignments(ctx, traceID, tenantID, userEmail, params)
}

// CreateAssignment persists a strategy assignment.
func (u *StrategyUsecase) CreateAssignment(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	return u.core.CreateStrategyAssignment(ctx, traceID, tenantID, userEmail, body)
}

// CleanQueue persists a queue-clean action.
func (u *StrategyUsecase) CleanQueue(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	return u.core.CleanStrategyQueue(ctx, traceID, tenantID, userEmail, body)
}
