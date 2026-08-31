package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// RolesHandler serves /api/v1/admin/roles and /api/v1/admin/permissions.
type RolesHandler struct {
	roles *usecases.RolesUsecase
}

// NewRolesHandler creates a RolesHandler.
func NewRolesHandler(roles *usecases.RolesUsecase) *RolesHandler {
	return &RolesHandler{roles: roles}
}

func (h *RolesHandler) requireAdmin(c *gin.Context) (*middleware.CognitoContext, bool) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil || ctx.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para realizar esta acción."}})
		return nil, false
	}
	return ctx, true
}

func (h *RolesHandler) requestMeta(c *gin.Context) (traceID, tenantID string) {
	if v, ok := c.Get("trace_id"); ok {
		traceID, _ = v.(string)
	}
	if v, ok := c.Get("tenant_id"); ok {
		tenantID, _ = v.(string)
	}
	return traceID, tenantID
}

// ListRoles handles GET /api/v1/admin/roles.
func (h *RolesHandler) ListRoles(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	traceID, tenantID := h.requestMeta(c)
	activeOnly := strings.EqualFold(c.Query("active"), "true")
	result, err := h.roles.ListRoles(c.Request.Context(), traceID, tenantID, ctx.Email, activeOnly)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RolesListFailed, "No se pudo cargar el listado de roles.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetRole handles GET /api/v1/admin/roles/:code.
func (h *RolesHandler) GetRole(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	traceID, tenantID := h.requestMeta(c)
	result, err := h.roles.GetRole(c.Request.Context(), c.Param("code"), traceID, tenantID, ctx.Email)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RoleMutationFailed, "No se pudo cargar el rol.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// CreateRole handles POST /api/v1/admin/roles.
func (h *RolesHandler) CreateRole(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}
	traceID, tenantID := h.requestMeta(c)
	result, err := h.roles.CreateRole(c.Request.Context(), traceID, tenantID, ctx.Email, body)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RoleMutationFailed, "No se pudo crear el rol.")
		return
	}
	c.JSON(http.StatusCreated, result)
}

// UpdateRole handles PATCH /api/v1/admin/roles/:code.
func (h *RolesHandler) UpdateRole(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}
	traceID, tenantID := h.requestMeta(c)
	result, err := h.roles.UpdateRole(c.Request.Context(), c.Param("code"), traceID, tenantID, ctx.Email, body)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RoleMutationFailed, "No se pudo actualizar el rol.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// ReplacePermissions handles PUT /api/v1/admin/roles/:code/permissions.
func (h *RolesHandler) ReplacePermissions(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}
	traceID, tenantID := h.requestMeta(c)
	result, err := h.roles.ReplaceRolePermissions(c.Request.Context(), c.Param("code"), traceID, tenantID, ctx.Email, body)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RoleMutationFailed, "No se pudieron actualizar los permisos del rol.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// ListPermissions handles GET /api/v1/admin/permissions.
func (h *RolesHandler) ListPermissions(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	traceID, tenantID := h.requestMeta(c)
	result, err := h.roles.ListPermissions(c.Request.Context(), traceID, tenantID, ctx.Email, c.Query("module"))
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RolesListFailed, "No se pudo cargar el catálogo de permisos.")
		return
	}
	c.JSON(http.StatusOK, result)
}

// ListRoleAuditLog handles GET /api/v1/admin/roles/:code/audit-log.
func (h *RolesHandler) ListRoleAuditLog(c *gin.Context) {
	ctx, ok := h.requireAdmin(c)
	if !ok {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	traceID, tenantID := h.requestMeta(c)
	result, err := h.roles.ListRoleAuditLog(c.Request.Context(), c.Param("code"), traceID, tenantID, ctx.Email, limit)
	if err != nil {
		writeBusinessOrFallback(c, err, domain.RolesListFailed, "No se pudo cargar la bitácora del rol.")
		return
	}
	c.JSON(http.StatusOK, result)
}
