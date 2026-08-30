package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// UsersHandler handles user management HTTP endpoints.
type UsersHandler struct {
	users *usecases.UsersUsecase
}

// NewUsersHandler creates a new UsersHandler.
func NewUsersHandler(users *usecases.UsersUsecase) *UsersHandler {
	return &UsersHandler{users: users}
}

func usersTraceTenant(c *gin.Context) (traceID, tenantID string) {
	if v, ok := c.Get("trace_id"); ok {
		if s, ok := v.(string); ok {
			traceID = s
		}
	}
	if v, ok := c.Get("tenant_id"); ok {
		if s, ok := v.(string); ok {
			tenantID = s
		}
	}
	if tenantID == "" {
		tenantID = c.GetHeader("X-Tenant-Id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	return traceID, tenantID
}

// ListUsers handles GET /api/v1/admin/users (admin only)
func (h *UsersHandler) ListUsers(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.ListUsers(c.Request.Context(), traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UsersListFailed, "No se pudo cargar el listado de usuarios.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// CreateUser handles POST /api/v1/admin/users (admin only)
func (h *UsersHandler) CreateUser(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}
	var req domain.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": domain.ValidationFailed, "message": "Solicitud inválida."}})
		return
	}
	if err := req.NormalizeAndValidate(); err != nil {
		writeBusinessOrFallback(c, err, domain.ValidationFailed, "Validacion fallida.")
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.CreateUser(c.Request.Context(), traceID, tenantID, ctx.Email, req.ToBody())
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserCreateFailed, "conflicto en procesar solicitud de alta de cliente")
		return
	}
	c.JSON(http.StatusCreated, result)
}

// UpdateUser handles PATCH/PUT /api/v1/admin/users/:userId (admin only)
func (h *UsersHandler) UpdateUser(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}
	userID, _ := url.PathUnescape(c.Param("userId"))
	userID = strings.TrimSpace(userID)
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": domain.ValidationFailed, "message": "Solicitud inválida."}})
		return
	}
	var req domain.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": domain.ValidationFailed, "message": "Solicitud inválida."}})
		return
	}
	if err := req.NormalizeAndValidate(); err != nil {
		writeBusinessOrFallback(c, err, domain.ValidationFailed, "Validacion fallida.")
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.UpdateUser(c.Request.Context(), userID, traceID, tenantID, ctx.Email, req.ToBody())
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserCreateFailed, "No se pudo actualizar el usuario.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// ResetPassword handles POST /api/v1/admin/users/:userId/reset-password (admin only)
func (h *UsersHandler) ResetPassword(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}
	userID, _ := url.PathUnescape(c.Param("userId"))
	userID = strings.TrimSpace(userID)
	var req domain.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": domain.ValidationFailed, "message": "Solicitud inválida."}})
		return
	}
	if err := req.ValidateEmail(); err != nil {
		writeBusinessOrFallback(c, err, domain.ValidationFailed, "email is required")
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.ResetPassword(c.Request.Context(), userID, req.Email, traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserCreateFailed, "No se pudo reiniciar la contraseña.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetMyPermissions handles GET /api/v1/collections/me/permissions
func (h *UsersHandler) GetMyPermissions(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.GetMyPermissions(c.Request.Context(), traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserPermissionsLoad, "No se pudieron cargar los permisos del usuario.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// ListMyTenants handles GET /api/v1/collections/me/tenants
func (h *UsersHandler) ListMyTenants(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.ListMyTenants(c.Request.Context(), traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserTenantsListFailed, "No se pudieron cargar las marcas disponibles para el usuario.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// ListTenantSyncStatus handles GET /api/v1/admin/tenants (supervisor, manager, admin).
func (h *UsersHandler) ListTenantSyncStatus(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || !canViewTenantSyncStatus(ctx.Role) {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	result, err := h.users.ListTenantSyncStatus(c.Request.Context(), traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserTenantsListFailed, "No se pudo cargar el estado de sincronización de las marcas.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// RecordLastLogin handles POST /api/v1/auth/last-login
func (h *UsersHandler) RecordLastLogin(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}
	traceID, tenantID := usersTraceTenant(c)
	err := h.users.RecordLastLogin(c.Request.Context(), traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.UserLastLoginRecord, "No se pudo registrar el último acceso del usuario.")
		return
	}
	c.Status(http.StatusNoContent)
}

func canViewTenantSyncStatus(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "supervisor", "manager":
		return true
	default:
		return false
	}
}
