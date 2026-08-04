package usecases

import (
	"context"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

// UsersUsecase handles user management business logic.
type UsersUsecase struct {
	core *coreclient.CoreClient
}

// NewUsersUsecase creates a new UsersUsecase.
func NewUsersUsecase(core *coreclient.CoreClient) *UsersUsecase {
	return &UsersUsecase{core: core}
}

// ListUsers gets the application users catalog.
func (u *UsersUsecase) ListUsers(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.ListUsers(ctx, traceID, tenantID, userEmail)
}

// CreateUser creates an application user.
func (u *UsersUsecase) CreateUser(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	return u.core.CreateUser(ctx, traceID, tenantID, userEmail, body)
}

// UpdateUser updates an application user.
func (u *UsersUsecase) UpdateUser(ctx context.Context, userID, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	return u.core.UpdateUser(ctx, userID, traceID, tenantID, userEmail, body)
}

// RecordLastLogin records the user's login timestamp.
func (u *UsersUsecase) RecordLastLogin(ctx context.Context, traceID, tenantID, userEmail string) error {
	return u.core.RecordLastLogin(ctx, traceID, tenantID, userEmail)
}

// GetMyPermissions gets the current user's application scopes and module permissions.
func (u *UsersUsecase) GetMyPermissions(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.GetMyPermissions(ctx, traceID, tenantID, userEmail)
}

// ListMyTenants gets tenants the current user may operate on.
func (u *UsersUsecase) ListMyTenants(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.ListMyTenants(ctx, traceID, tenantID, userEmail)
}

// ListTenantSyncStatus gets tenant sync status (admin only).
func (u *UsersUsecase) ListTenantSyncStatus(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.ListTenantSyncStatus(ctx, traceID, tenantID, userEmail)
}
