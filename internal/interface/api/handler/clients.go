package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// ClientsHandler handles all client-related HTTP endpoints.
type ClientsHandler struct {
	clients *usecases.ClientsUsecase
}

// NewClientsHandler creates a new ClientsHandler.
func NewClientsHandler(clients *usecases.ClientsUsecase) *ClientsHandler {
	return &ClientsHandler{clients: clients}
}

// ListClients handles GET /api/v1/collections/clients
func (h *ClientsHandler) ListClients(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	params := usecases.ClientListParams{
		Search: c.Query("search"),
		Limit:  limit,
		Offset: offset,
	}

	result, err := h.clients.ListClients(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, params)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.ClientsListFailed, "message": "No se pudo cargar el listado de clientes."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListClientContacts handles GET /api/v1/collections/clients/contacts
func (h *ClientsHandler) ListClientContacts(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 100
	}

	result, err := h.clients.ListClientContacts(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, limit, offset)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.ClientContactsListFailed, "message": "No se pudo cargar la información de contacto de clientes."}})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListAtRisk handles GET /api/v1/collections/clients/at-risk
func (h *ClientsHandler) ListAtRisk(c *gin.Context) {
	ctx := middleware.GetCognitoContext(c)
	if ctx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
		return
	}

	traceID, _ := c.Get("trace_id")
	tenantID, _ := c.Get("tenant_id")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 200
	}

	result, err := h.clients.ListAtRisk(c.Request.Context(), traceID.(string), tenantID.(string), ctx.Email, limit, offset)
	if err != nil {
		if bizErr, ok := err.(*domain.BusinessError); ok {
			c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"error": map[string]any{"code": domain.AtRiskClientsListFailed, "message": "No se pudieron cargar los clientes en riesgo."}})
		return
	}

	c.JSON(http.StatusOK, result)
}
