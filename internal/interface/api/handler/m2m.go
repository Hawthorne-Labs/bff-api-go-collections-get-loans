package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// M2MWhoami handles GET /api/m2m/whoami
// Machine-to-machine endpoint — authenticated by Kong/API Gateway.
func M2MWhoami(c *gin.Context) {
	sub := c.GetHeader("X-Auth-Sub")
	if sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing X-Auth-Sub"})
		return
	}
	jti := c.GetHeader("X-Auth-Jti")
	c.JSON(http.StatusOK, gin.H{"sub": sub, "jti": jti})
}
