package handler

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/fieldcrypto"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// CryptoSessionHandler handles the local P-256 ECDH crypto-session handshake.
type CryptoSessionHandler struct {
	mgr *fieldcrypto.SessionManager
}

// NewCryptoSessionHandler creates a new handler.
func NewCryptoSessionHandler(mgr *fieldcrypto.SessionManager) *CryptoSessionHandler {
	return &CryptoSessionHandler{mgr: mgr}
}

type handshakeRequest struct {
	ClientPublicKey string `json:"clientPublicKey"`
}

// Handshake handles POST /api/v1/collections/crypto-session
func (h *CryptoSessionHandler) Handshake(c *gin.Context) {
	var req handshakeRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil || req.ClientPublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 90100, "message": "Solicitud de cifrado inválida."}})
		return
	}

	// Resolve subject/scope from Cognito context
	sub := "user"
	scope := "collections:read"
	if cc := middleware.GetCognitoContext(c); cc != nil {
		if cc.Sub != "" {
			sub = cc.Sub
		}
		if cc.Scope != "" {
			scope = cc.Scope
		}
	}

	result, err := h.mgr.Handshake(req.ClientPublicKey, sub, scope)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 90101, "message": "Material de cifrado inválido."}})
		return
	}

	c.JSON(http.StatusOK, result)
}
