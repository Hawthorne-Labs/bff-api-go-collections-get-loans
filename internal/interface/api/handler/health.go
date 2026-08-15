package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HealthHandler handles the health check endpoint.
type HealthHandler struct{}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Check handles GET /health
func (h *HealthHandler) Check(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Liveness handles GET /health/live
func (h *HealthHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "live"})
}

// Readiness handles GET /health/ready
func (h *HealthHandler) Readiness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
