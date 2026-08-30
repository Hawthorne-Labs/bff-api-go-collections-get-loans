package usecases

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/cognito"
)

// IdentityProvisioner is the Cognito subset used by UserIdentitySaga.
type IdentityProvisioner interface {
	AdminSyncUser(ctx context.Context, email, name, role string, active bool) (cognito.ProvisioningResult, error)
	AdminResetOrSyncUser(ctx context.Context, email, name, role string, active bool) (cognito.ProvisioningResult, error)
}

var (
	errIdentitySyncFailed = errors.New("identity provider sync failed")
	errManagedUserMissing = errors.New("managed user not found")
)

// usersCore is the Core subset for identity user management.
type usersCore interface {
	ListUsers(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error)
	CreateUser(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error)
	UpdateUser(ctx context.Context, userID, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error)
	RecordLastLogin(ctx context.Context, traceID, tenantID, userEmail string) error
	GetMyPermissions(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error)
	ListMyTenants(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error)
	ListTenantSyncStatus(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error)
}

// UsersUsecase handles user management business logic.
type UsersUsecase struct {
	core     usersCore
	identity IdentityProvisioner
}

// NewUsersUsecase creates a new UsersUsecase.
func NewUsersUsecase(core usersCore, identity IdentityProvisioner) *UsersUsecase {
	return &UsersUsecase{core: core, identity: identity}
}

// ListUsers gets the application users catalog.
func (u *UsersUsecase) ListUsers(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.ListUsers(ctx, traceID, tenantID, userEmail)
}

// CreateUser runs Core+Cognito identity saga (Python UserIdentitySaga.create).
func (u *UsersUsecase) CreateUser(ctx context.Context, traceID, tenantID, actorEmail string, body map[string]any) (map[string]any, error) {
	if u.identity == nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "conflicto en procesar solicitud de alta de cliente")
	}
	staged := copyMap(body)
	// anti-regresion: BUG-0415
	staged["activo"] = false
	created, err := u.core.CreateUser(ctx, traceID, tenantID, actorEmail, staged)
	if err != nil {
		return nil, err
	}
	userID, err := extractUserID(created)
	if err != nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "conflicto en procesar solicitud de alta de cliente")
	}
	identity, err := u.identity.AdminSyncUser(ctx,
		strField(body, "email"),
		strField(body, "nombre"),
		strField(body, "rol"),
		true,
	)
	if err != nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "conflicto en procesar solicitud de alta de cliente")
	}
	activated, err := u.core.UpdateUser(ctx, userID, traceID, tenantID, actorEmail, mutableBody(body, true, ""))
	if err != nil {
		return nil, err
	}
	out := copyMap(activated)
	out["cognito"] = identity.ToPublicMap()
	return out, nil
}

// UpdateUser runs Core+Cognito identity saga (Python UserIdentitySaga.update).
func (u *UsersUsecase) UpdateUser(ctx context.Context, userID, traceID, tenantID, actorEmail string, body map[string]any) (map[string]any, error) {
	if u.identity == nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "No se pudo actualizar el usuario.")
	}
	target, err := u.findUser(ctx, traceID, tenantID, actorEmail, userID)
	if err != nil {
		if errors.Is(err, errManagedUserMissing) {
			return nil, domain.NewHTTPBusinessError(404, domain.UserCreateFailed, "Usuario no encontrado.")
		}
		return nil, err
	}
	desiredActive := boolField(target, "activo")
	if raw, ok := body["activo"].(bool); ok {
		desiredActive = raw
	}
	currentEmail := strings.TrimSpace(strField(target, "email"))
	requestedEmail := strings.TrimSpace(strField(body, "email"))
	desiredEmail := requestedEmail
	if desiredEmail == "" {
		desiredEmail = currentEmail
	}
	// anti-regresion: BUG-0844
	emailChanged := desiredEmail != "" && !strings.EqualFold(desiredEmail, currentEmail)

	emailForStage := ""
	if emailChanged {
		emailForStage = desiredEmail
	}
	staged, err := u.core.UpdateUser(ctx, userID, traceID, tenantID, actorEmail, mutableBody(body, false, emailForStage))
	if err != nil {
		return nil, err
	}
	if emailChanged && currentEmail != "" {
		if _, err := u.identity.AdminSyncUser(ctx, currentEmail, strField(body, "nombre"), strField(body, "rol"), false); err != nil {
			return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "No se pudo actualizar el usuario.")
		}
	}
	identity, err := u.identity.AdminSyncUser(ctx, desiredEmail, strField(body, "nombre"), strField(body, "rol"), desiredActive)
	if err != nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "No se pudo actualizar el usuario.")
	}
	if !desiredActive {
		out := copyMap(staged)
		out["cognito"] = identity.ToPublicMap()
		return out, nil
	}
	activated, err := u.core.UpdateUser(ctx, userID, traceID, tenantID, actorEmail, mutableBody(body, true, emailForStage))
	if err != nil {
		return nil, err
	}
	out := copyMap(activated)
	out["cognito"] = identity.ToPublicMap()
	return out, nil
}

// ResetPassword resets Cognito password for user_id + email match.
func (u *UsersUsecase) ResetPassword(ctx context.Context, userID, email, traceID, tenantID, actorEmail string) (map[string]any, error) {
	if u.identity == nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "No se pudo reiniciar la contraseña.")
	}
	target, err := u.findUser(ctx, traceID, tenantID, actorEmail, userID)
	if err != nil {
		if errors.Is(err, errManagedUserMissing) {
			return nil, domain.NewHTTPBusinessError(404, domain.UserCreateFailed, "Usuario no encontrado para reinicio de contraseña.")
		}
		return nil, err
	}
	if !strings.EqualFold(strField(target, "email"), strings.TrimSpace(email)) {
		return nil, domain.NewHTTPBusinessError(404, domain.UserCreateFailed, "Usuario no encontrado para reinicio de contraseña.")
	}
	identity, err := u.identity.AdminResetOrSyncUser(ctx,
		strField(target, "email"),
		strField(target, "nombre"),
		strField(target, "rol"),
		boolField(target, "activo"),
	)
	if err != nil {
		return nil, domain.NewHTTPBusinessError(502, domain.UserCreateFailed, "No se pudo reiniciar la contraseña.")
	}
	return map[string]any{"cognito": identity.ToPublicMap()}, nil
}

// RecordLastLogin records the user's login timestamp.
func (u *UsersUsecase) RecordLastLogin(ctx context.Context, traceID, tenantID, userEmail string) error {
	return u.core.RecordLastLogin(ctx, traceID, tenantID, userEmail)
}

// GetMyPermissions gets permissions + tenants (Python parity).
func (u *UsersUsecase) GetMyPermissions(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	permissions, err := u.core.GetMyPermissions(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	tenants, err := u.core.ListMyTenants(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return mergePermissionsWithTenants(permissions, tenants), nil
}

// ListMyTenants gets tenants the current user may operate on.
func (u *UsersUsecase) ListMyTenants(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.ListMyTenants(ctx, traceID, tenantID, userEmail)
}

// ListTenantSyncStatus gets tenant sync status for supervisor, manager, and admin.
func (u *UsersUsecase) ListTenantSyncStatus(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	return u.core.ListTenantSyncStatus(ctx, traceID, tenantID, userEmail)
}

func (u *UsersUsecase) findUser(ctx context.Context, traceID, tenantID, actorEmail, userID string) (map[string]any, error) {
	listed, err := u.core.ListUsers(ctx, traceID, tenantID, actorEmail)
	if err != nil {
		return nil, err
	}
	items, _ := listed["items"].([]any)
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if strField(m, "id") == userID {
			return m, nil
		}
	}
	return nil, errManagedUserMissing
}

// anti-regresion: BUG-1007
func mergePermissionsWithTenants(permissions, tenantsResp map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range permissions {
		out[k] = v
	}
	items := []any{}
	if tenantsResp != nil {
		if raw, ok := tenantsResp["items"].([]any); ok && raw != nil {
			items = raw
		}
	}
	out["tenants"] = items
	return out
}

func extractUserID(response map[string]any) (string, error) {
	if data, ok := response["data"].(map[string]any); ok {
		if id := strField(data, "id"); id != "" {
			return id, nil
		}
	}
	if id := strField(response, "id"); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("%w: missing user id", errIdentitySyncFailed)
}

func mutableBody(body map[string]any, active bool, email string) map[string]any {
	// anti-regresion: BUG-0844
	out := map[string]any{}
	for k, v := range body {
		if k == "email" {
			continue
		}
		out[k] = v
	}
	out["activo"] = active
	if email != "" {
		out["email"] = email
	}
	return out
}

func copyMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func boolField(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}
