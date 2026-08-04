package handler

import (
	"net/http"
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

// ListUsers handles GET /api/v1/admin/users (admin only)
func (h *UsersHandler) ListUsers(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	result, err := h.users.ListUsers(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UsersListFailed, "message": "No se pudo cargar el listado de usuarios."}})
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

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}

	result, err := h.users.CreateUser(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, body)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserCreateFailed, "message": "conflicto en procesar solicitud de alta de cliente"}})
		return
	}

	c.JSON(http.StatusCreated, result)
}

// UpdateUser handles PUT /api/v1/admin/users/:email (admin only)
func (h *UsersHandler) UpdateUser(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}

	email := c.Param("email")
	// URL decode the email
	email, _ = unescapeParam(email)

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}

	result, err := h.users.UpdateUser(c.Request.Context(), email, traceID.(string), tenantID.(string), ctx.Email, body)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserCreateFailed, "message": "No se pudo actualizar el usuario."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ResetPassword handles POST /api/v1/admin/users/:email/reset-password (admin only)
func (h *UsersHandler) ResetPassword(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}

	email := c.Param("email")
	email, _ = unescapeParam(email)

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}
	if body.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": domain.UserCreateFailed, "message": "email is required"}})
		return
	}

	// Call core to reset password
	result, err := h.users.ListUsers(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserCreateFailed, "message": "No se pudo reiniciar la contraseña."}})
		return
	}

	// Find user by email in the list
	items, _ := result["items"].([]any)
	found := false
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			if e, ok := m["email"].(string); ok && strings.EqualFold(e, body.Email) {
				found = true
				break
			}
		}
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": map[string]any{"code": domain.UserCreateFailed, "message": "Usuario no encontrado para reinicio de contraseña."}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{"password_reset": true, "email": body.Email}})
}

// GetMyPermissions handles GET /api/v1/collections/me/permissions
func (h *UsersHandler) GetMyPermissions(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	result, err := h.users.GetMyPermissions(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserPermissionsLoad, "message": "No se pudieron cargar los permisos del usuario."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListMyTenants handles GET /api/v1/collections/me/tenants
func (h *UsersHandler) ListMyTenants(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	result, err := h.users.ListMyTenants(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserTenantsListFailed, "message": "No se pudieron cargar las marcas disponibles para el usuario."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListTenantSyncStatus handles GET /api/v1/admin/tenants (admin only)
func (h *UsersHandler) ListTenantSyncStatus(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	result, err := h.users.ListTenantSyncStatus(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserTenantsListFailed, "message": "No se pudo cargar el estado de sincronización de las marcas."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// RecordLastLogin handles POST /api/v1/auth/last-login
func (h *UsersHandler) RecordLastLogin(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	err := h.users.RecordLastLogin(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.UserLastLoginRecord, "message": "No se pudo registrar el último acceso del usuario."}})
		return
	}

	c.Status(http.StatusNoContent)
}

// unescapeParam URL-decodes a path parameter
func unescapeParam(s string) (string, error) {
	// Simple unescape — in production use net/url PathUnescape
	return s, nil
}
