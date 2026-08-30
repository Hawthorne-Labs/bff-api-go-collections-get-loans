package handler

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/fieldcrypto"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

// CryptoSessionHandler handles the P-256 ECDH crypto-session handshake.
type CryptoSessionHandler struct {
	mgr             any
	tenantAuthority fieldcrypto.TenantAuthority
}

// NewCryptoSessionHandler creates a new handler.
func NewCryptoSessionHandler(mgr any, tenantAuthority fieldcrypto.TenantAuthority) *CryptoSessionHandler {
	if tenantAuthority == nil {
		tenantAuthority = fieldcrypto.GetTenantAuthority()
	}
	return &CryptoSessionHandler{mgr: mgr, tenantAuthority: tenantAuthority}
}

type handshakeRequest struct {
	ClientPublicKey string `json:"clientPublicKey"`
}

// Handshake handles POST /api/v1/collections/crypto-session
func (h *CryptoSessionHandler) Handshake(c *gin.Context) {
	cc := middleware.GetCognitoContext(c)
	if cc == nil || cc.Sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return
	}
	scopes := map[string]struct{}{}
	for _, s := range splitHandshakeScopes(cc.Scope) {
		scopes[s] = struct{}{}
	}
	if _, ok := scopes["collections:read"]; !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para esta operación."}})
		return
	}

	var req handshakeRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil || req.ClientPublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 90100, "message": "Solicitud de cifrado inválida."}})
		return
	}

	sub := "user"
	scope := "collections:read"
	email := ""
	if cc.Sub != "" {
		sub = cc.Sub
	}
	if cc.Scope != "" {
		scope = cc.Scope
	}
	email = cc.Email

	switch mgr := h.mgr.(type) {
	case *fieldcrypto.StatelessCryptoSessionManager:
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 90109, "message": fieldcrypto.CatalogErrorMessage(90109)}})
			return
		}
		authorized, err := h.tenantAuthority.Resolve(
			c.Request.Context(),
			authorization,
			c.GetHeader("X-Tenant-Id"),
			email,
			true,
			c.GetHeader("X-Trace-Id"),
		)
		if err != nil {
			status, body := fieldcrypto.PublicErrorEnvelope(err)
			c.JSON(status, body)
			return
		}
		accessTokenHash, err := fieldcrypto.HashAccessToken(authorization)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": 90109, "message": fieldcrypto.CatalogErrorMessage(90109)}})
			return
		}
		result, err := mgr.Handshake(req.ClientPublicKey, sub, scope, authorized.TenantDigest, accessTokenHash)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 90101, "message": fieldcrypto.CatalogErrorMessage(90101)}})
			return
		}
		c.JSON(http.StatusOK, result)
	case *fieldcrypto.CryptoSessionManager:
		result, err := mgr.Handshake(req.ClientPublicKey, sub, scope)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": map[string]any{"code": 90101, "message": fieldcrypto.CatalogErrorMessage(90101)}})
			return
		}
		c.JSON(http.StatusOK, result)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": map[string]any{"code": 90012, "message": "Error interno."}})
	}
}

func splitHandshakeScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	out := make([]string, 0)
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if i > start {
				out = append(out, scope[start:i])
			}
			start = i + 1
		}
	}
	return out
}
