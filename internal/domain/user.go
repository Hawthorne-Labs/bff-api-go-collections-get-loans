package domain

// CreateUserRequest represents the payload for creating an application user.
// Tenant normalization and scope validation mirrors the Python FastAPI model.
type CreateUserRequest struct {
	Email     string              `json:"email" validate:"min=3,max=120"`
	Nombre    string              `json:"nombre" validate:"min=1,max=120"`
	Rol       string              `json:"rol" validate:"min=1,max=40"`
	Tenant    string              `json:"tenant" validate:"min=1,max=80"`
	Tenants   []string            `json:"tenants,omitempty"`
	ManagerID *string             `json:"managerId,omitempty"`
	Modulos   map[string][]string `json:"modulos,omitempty"`
}

// ValidateTenantScope checks tenant scope rules: supervisor can have >1 tenant, others only 1.
func (r *CreateUserRequest) ValidateTenantScope() error {
	if r.Tenant == "" {
		return &BusinessError{Code: UserCreateFailed, Message: "tenant is required"}
	}
	if len(r.Tenants) == 0 {
		r.Tenants = []string{r.Tenant}
	}
	role := r.Rol
	if role != "supervisor" && len(r.Tenants) > 1 {
		return &BusinessError{Code: UserCreateFailed, Message: "solo el supervisor puede tener más de una marca"}
	}
	return nil
}

// UpdateUserRequest represents the payload for updating an application user.
type UpdateUserRequest struct {
	Nombre    string              `json:"nombre" validate:"min=1,max=120"`
	Rol       string              `json:"rol" validate:"min=1,max=40"`
	Tenant    string              `json:"tenant" validate:"min=1,max=80"`
	Tenants   []string            `json:"tenants,omitempty"`
	ManagerID *string             `json:"managerId,omitempty"`
	Modulos   map[string][]string `json:"modulos,omitempty"`
	Activo    *bool               `json:"activo,omitempty"`
}

// ValidateTenantScope checks tenant scope rules for updates.
func (r *UpdateUserRequest) ValidateTenantScope() error {
	if r.Tenant == "" {
		return &BusinessError{Code: UserCreateFailed, Message: "tenant is required"}
	}
	if len(r.Tenants) == 0 {
		r.Tenants = []string{r.Tenant}
	}
	role := r.Rol
	if role != "supervisor" && len(r.Tenants) > 1 {
		return &BusinessError{Code: UserCreateFailed, Message: "solo el supervisor puede tener más de una marca"}
	}
	return nil
}

// ResetPasswordRequest represents the payload for resetting a user's password.
type ResetPasswordRequest struct {
	Email string `json:"email" validate:"min=3,max=120"`
}

// ValidateEmail ensures the email field is non-empty.
func (r *ResetPasswordRequest) ValidateEmail() error {
	if r.Email == "" {
		return &BusinessError{Code: UserCreateFailed, Message: "email is required"}
	}
	return nil
}
