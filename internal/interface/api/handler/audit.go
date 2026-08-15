package handler

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

// AuditHandler handles audit log proxy endpoints.
type AuditHandler struct {
	core *coreclient.CoreClient
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(core *coreclient.CoreClient) *AuditHandler {
	return &AuditHandler{core: core}
}

// Recent returns recent audit events.
// GET /api/v1/audit/recent
func (h *AuditHandler) Recent(c *gin.Context) {
	traceID, _ := c.Get("trace_id")
	tenantID := c.DefaultQuery("tenant_id", "default")

	resp, err := h.core.ForwardGet(c.Request.Context(), "/api/v1/audit/recent",
		map[string]string{"tenant_id": tenantID},
		traceID.(string), c.GetString("request_id"), c.GetString("correlation_id"), c.GetHeader("traceparent"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": gin.H{"code": "DEPENDENT_SERVICE_FAILED", "message": "No fue posible consultar auditoria."}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

// ByEntity returns audit events for a specific entity.
// GET /api/v1/audit/events
func (h *AuditHandler) ByEntity(c *gin.Context) {
	entityID := c.Query("entity_id")
	if entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "entity_id es requerido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	resp, err := h.core.ForwardGet(c.Request.Context(), "/api/v1/audit/events",
		map[string]string{"entity_id": entityID},
		traceID.(string), c.GetString("request_id"), c.GetString("correlation_id"), c.GetHeader("traceparent"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": gin.H{"code": "DEPENDENT_SERVICE_FAILED", "message": "No fue posible consultar auditoria."}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

// Integrity returns audit integrity check for an entity.
// GET /api/v1/audit/integrity
func (h *AuditHandler) Integrity(c *gin.Context) {
	entityID := c.Query("entity_id")
	if entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "entity_id es requerido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	resp, err := h.core.ForwardGet(c.Request.Context(), "/api/v1/audit/integrity",
		map[string]string{"entity_id": entityID},
		traceID.(string), c.GetString("request_id"), c.GetString("correlation_id"), c.GetHeader("traceparent"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": gin.H{"code": "DEPENDENT_SERVICE_FAILED", "message": "No fue posible verificar integridad."}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}
