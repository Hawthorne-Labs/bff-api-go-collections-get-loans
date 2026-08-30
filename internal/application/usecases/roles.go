package usecases

import (
	"context"
	"log"
	"strings"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

// RoleCoreClient is the Core HTTP surface used by RolesUsecase.
type RoleCoreClient interface {
	ListRoles(ctx context.Context, traceID, tenantID, userEmail string, activeOnly bool) (map[string]any, error)
	GetRole(ctx context.Context, code, traceID, tenantID, userEmail string) (map[string]any, error)
	CreateRole(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error)
	UpdateRole(ctx context.Context, code, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error)
	ReplaceRolePermissions(ctx context.Context, code, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error)
	ListPermissions(ctx context.Context, traceID, tenantID, userEmail, module string) (map[string]any, error)
}

// RoleGroupProvisioner creates Cognito groups for dynamic roles.
type RoleGroupProvisioner interface {
	EnsureGroup(ctx context.Context, code, description string) (created bool, err error)
}

// RolesUsecase proxies Core role APIs and runs the Cognito CreateGroup saga.
type RolesUsecase struct {
	core    RoleCoreClient
	cognito RoleGroupProvisioner
}

// NewRolesUsecase creates a RolesUsecase.
func NewRolesUsecase(core RoleCoreClient, cognito RoleGroupProvisioner) *RolesUsecase {
	return &RolesUsecase{core: core, cognito: cognito}
}

// ListRoles proxies Core list roles.
func (u *RolesUsecase) ListRoles(ctx context.Context, traceID, tenantID, userEmail string, activeOnly bool) (map[string]any, error) {
	return u.core.ListRoles(ctx, traceID, tenantID, userEmail, activeOnly)
}

// GetRole proxies Core get role.
func (u *RolesUsecase) GetRole(ctx context.Context, code, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.GetRole(ctx, code, traceID, tenantID, userEmail)
}

// CreateRole persists via Core then EnsureGroup; compensates with isActive=false on Cognito failure.
func (u *RolesUsecase) CreateRole(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	payload := normalizeRoleWriteBody(body)
	created, err := u.core.CreateRole(ctx, traceID, tenantID, userEmail, payload)
	if err != nil {
		return nil, err
	}

	code := roleCodeFrom(created, payload)
	description := roleDescriptionFrom(created, payload)
	if u.cognito == nil {
		return withCognitoMeta(created, code, false), nil
	}

	groupCreated, ensureErr := u.cognito.EnsureGroup(ctx, code, description)
	if ensureErr != nil {
		inactive := false
		if _, compErr := u.core.UpdateRole(ctx, code, traceID, tenantID, userEmail, map[string]any{"isActive": inactive}); compErr != nil {
			log.Printf("role cognito compensation deactivate failed role_code=%s", code)
		}
		return nil, domain.NewHTTPBusinessError(
			502,
			domain.RoleMutationFailed,
			"No se pudo provisionar el grupo Cognito del rol.",
		)
	}

	return withCognitoMeta(created, code, groupCreated), nil
}

// UpdateRole proxies Core patch role.
func (u *RolesUsecase) UpdateRole(ctx context.Context, code, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	return u.core.UpdateRole(ctx, code, traceID, tenantID, userEmail, normalizeRoleWriteBody(body))
}

// ReplaceRolePermissions proxies Core replace permissions.
func (u *RolesUsecase) ReplaceRolePermissions(ctx context.Context, code, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	return u.core.ReplaceRolePermissions(ctx, code, traceID, tenantID, userEmail, body)
}

// ListPermissions proxies Core permission catalog.
func (u *RolesUsecase) ListPermissions(ctx context.Context, traceID, tenantID, userEmail, module string) (map[string]any, error) {
	return u.core.ListPermissions(ctx, traceID, tenantID, userEmail, module)
}

func withCognitoMeta(created map[string]any, code string, groupCreated bool) map[string]any {
	out := map[string]any{}
	for k, v := range created {
		out[k] = v
	}
	out["cognito"] = map[string]any{
		"group":   code,
		"created": groupCreated,
	}
	return out
}

func roleCodeFrom(created, payload map[string]any) string {
	if code, ok := created["code"].(string); ok && strings.TrimSpace(code) != "" {
		return strings.ToLower(strings.TrimSpace(code))
	}
	if code, ok := payload["code"].(string); ok {
		return strings.ToLower(strings.TrimSpace(code))
	}
	return ""
}

func roleDescriptionFrom(created, payload map[string]any) string {
	if d, ok := created["description"].(string); ok {
		return d
	}
	if d, ok := payload["description"].(string); ok {
		return d
	}
	return ""
}

// normalizeRoleWriteBody maps snake_case Python-compatible keys to Core camelCase.
func normalizeRoleWriteBody(body map[string]any) map[string]any {
	if body == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(body)+2)
	for k, v := range body {
		out[k] = v
	}
	if _, ok := out["displayName"]; !ok {
		if v, ok := out["display_name"]; ok {
			out["displayName"] = v
		}
	}
	if _, ok := out["isActive"]; !ok {
		if v, ok := out["is_active"]; ok {
			out["isActive"] = v
		}
	}
	return out
}
