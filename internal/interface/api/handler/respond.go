package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

func writeBizError(c *gin.Context, err error, fallbackCode int, fallbackMsg string) {
	if bizErr, ok := err.(*domain.BusinessError); ok {
		c.JSON(bizErr.Status(), gin.H{"error": map[string]any{"code": bizErr.Code, "message": bizErr.Message}})
		return
	}
	c.JSON(http.StatusBadGateway, gin.H{"error": map[string]any{"code": fallbackCode, "message": fallbackMsg}})
}

func writeBusinessOrFallback(c *gin.Context, err error, fallbackCode int, fallbackMsg string) {
	writeBizError(c, err, fallbackCode, fallbackMsg)
}
