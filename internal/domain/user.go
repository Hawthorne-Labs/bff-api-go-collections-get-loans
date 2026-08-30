package domain

import (
	"net/http"
	"strings"
)

const MaxPriority4DaysPastDue = 1825

// CreateUserRequest represents the payload for creating an application user.
type CreateUserRequest struct {
	Email     string              `json:"email"`
	Nombre    string              `json:"nombre"`
	Rol       string              `json:"rol"`
	Tenant    string              `json:"tenant"`
	Tenants   []string            `json:"tenants"`
	ManagerID *string             `json:"managerId"`
	Modulos   map[string][]string `json:"modulos"`
}

// NormalizeAndValidate applies Python CreateUserRequest rules.
func (r *CreateUserRequest) NormalizeAndValidate() error {
	r.Email = strings.TrimSpace(r.Email)
	r.Nombre = strings.TrimSpace(r.Nombre)
	r.Rol = strings.TrimSpace(r.Rol)
	r.Tenant = strings.TrimSpace(r.Tenant)
	r.Tenants = normalizeTenantList(r.Tenant, r.Tenants)
	if r.Tenant == "" && len(r.Tenants) > 0 {
		r.Tenant = r.Tenants[0]
	}
	if len(r.Email) < 3 || len(r.Email) > 120 || r.Nombre == "" || len(r.Nombre) > 120 || r.Rol == "" || len(r.Rol) > 40 {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "Validacion fallida.")
	}
	role := strings.ToLower(r.Rol)
	if role != "admin" && r.Tenant == "" {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "tenant is required")
	}
	if role != "supervisor" && role != "admin" && len(r.Tenants) > 1 {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "solo el supervisor puede tener más de una marca")
	}
	return nil
}

// ToBody maps to Core payload keys (Spanish field names).
func (r *CreateUserRequest) ToBody() map[string]any {
	body := map[string]any{
		"email":  r.Email,
		"nombre": r.Nombre,
		"rol":    r.Rol,
		"tenant": r.Tenant,
	}
	if len(r.Tenants) > 0 {
		body["tenants"] = r.Tenants
	}
	if r.ManagerID != nil {
		body["managerId"] = *r.ManagerID
	}
	if r.Modulos != nil {
		body["modulos"] = r.Modulos
	}
	return body
}

// UpdateUserRequest represents the payload for updating an application user.
type UpdateUserRequest struct {
	Email     *string             `json:"email"`
	Nombre    string              `json:"nombre"`
	Rol       string              `json:"rol"`
	Tenant    string              `json:"tenant"`
	Tenants   []string            `json:"tenants"`
	ManagerID *string             `json:"managerId"`
	Modulos   map[string][]string `json:"modulos"`
	Activo    *bool               `json:"activo"`
}

// NormalizeAndValidate applies Python UpdateUserRequest rules.
func (r *UpdateUserRequest) NormalizeAndValidate() error {
	r.Nombre = strings.TrimSpace(r.Nombre)
	r.Rol = strings.TrimSpace(r.Rol)
	r.Tenant = strings.TrimSpace(r.Tenant)
	if r.Email != nil {
		trimmed := strings.TrimSpace(*r.Email)
		r.Email = &trimmed
		if len(trimmed) > 0 && (len(trimmed) < 3 || len(trimmed) > 120) {
			return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "Validacion fallida.")
		}
	}
	r.Tenants = normalizeTenantList(r.Tenant, r.Tenants)
	if r.Tenant == "" && len(r.Tenants) > 0 {
		r.Tenant = r.Tenants[0]
	}
	if r.Nombre == "" || len(r.Nombre) > 120 || r.Rol == "" || len(r.Rol) > 40 {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "Validacion fallida.")
	}
	role := strings.ToLower(r.Rol)
	if role != "admin" && r.Tenant == "" {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "tenant is required")
	}
	if role != "supervisor" && role != "admin" && len(r.Tenants) > 1 {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "solo el supervisor puede tener más de una marca")
	}
	return nil
}

// ToBody maps to Core payload.
func (r *UpdateUserRequest) ToBody() map[string]any {
	body := map[string]any{
		"nombre": r.Nombre,
		"rol":    r.Rol,
		"tenant": r.Tenant,
	}
	if r.Email != nil && strings.TrimSpace(*r.Email) != "" {
		body["email"] = strings.TrimSpace(*r.Email)
	}
	if len(r.Tenants) > 0 {
		body["tenants"] = r.Tenants
	}
	if r.ManagerID != nil {
		body["managerId"] = *r.ManagerID
	}
	if r.Modulos != nil {
		body["modulos"] = r.Modulos
	}
	if r.Activo != nil {
		body["activo"] = *r.Activo
	}
	return body
}

// ResetPasswordRequest represents the payload for resetting a user's password.
type ResetPasswordRequest struct {
	Email string `json:"email"`
}

// ValidateEmail ensures the email field is non-empty.
func (r *ResetPasswordRequest) ValidateEmail() error {
	r.Email = strings.TrimSpace(r.Email)
	if len(r.Email) < 3 || len(r.Email) > 120 {
		return NewHTTPBusinessError(http.StatusUnprocessableEntity, ValidationFailed, "email is required")
	}
	return nil
}

func normalizeTenantList(primary string, tenants []string) []string {
	out := make([]string, 0, len(tenants)+1)
	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(primary)
	for _, t := range tenants {
		add(t)
	}
	return out
}
