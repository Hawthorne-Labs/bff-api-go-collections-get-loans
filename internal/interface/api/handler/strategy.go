package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// StrategyHandler handles all strategy/segmentation HTTP endpoints.
type StrategyHandler struct {
	strategy *usecases.StrategyUsecase
}

// NewStrategyHandler creates a new StrategyHandler.
func NewStrategyHandler(strategy *usecases.StrategyUsecase) *StrategyHandler {
	return &StrategyHandler{strategy: strategy}
}

// GetSegmentation handles GET /api/v1/collections/strategy/segmentation
func (h *StrategyHandler) GetSegmentation(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	marca := c.Query("marca")

	result, err := h.strategy.GetSegmentation(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, marca)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.StrategySegmentationFailed, "message": "No se pudo cargar la segmentación de estrategia."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListAssignments handles GET /api/v1/collections/strategy/assignments
func (h *StrategyHandler) ListAssignments(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 100 {
		limit = 50
	}

	marca := c.Query("marca")

	result, err := h.strategy.ListAssignments(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, limit, offset, marca)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.StrategyAssignmentsListFailed, "message": "No se pudo cargar el historial de asignaciones de estrategia."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// CreateAssignment handles POST /api/v1/collections/strategy/assignments
func (h *StrategyHandler) CreateAssignment(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}

	result, err := h.strategy.CreateAssignment(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, body)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.StrategyAssignmentCreateFailed, "message": "No se pudo guardar la asignación de estrategia."}})
		return
	}

	c.JSON(http.StatusCreated, result)
}

// CleanQueue handles POST /api/v1/collections/strategy/clean
func (h *StrategyHandler) CleanQueue(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 4000, "message": "Solicitud inválida."}})
		return
	}

	result, err := h.strategy.CleanQueue(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, body)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.StrategyQueueCleanFailed, "message": "No se pudo limpiar la cola de estrategia."}})
		return
	}

	c.JSON(http.StatusCreated, result)
}
