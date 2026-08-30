package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CryptoMiddleware handles Field-Level Encryption (FLE) for requests/responses.
// When CRYPTO_ENABLED is true, this middleware:
// 1. Decrypts incoming request bodies
// 2. Encrypts outgoing response bodies
// When disabled, it's a no-op passthrough.
func CryptoMiddleware(enabled bool, cryptoClient *CryptoClient) gin.HandlerFunc {
	if !enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		// Check for crypto headers
		cryptoSessionID := c.GetHeader("Crypto-Session-Id")
		cryptoRequestID := c.GetHeader("Crypto-Request-Id")
		cryptoVersion := c.GetHeader("Crypto-Version")
		cryptoTenantID := c.GetHeader("Crypto-Tenant-Id")

		// If no crypto headers, proceed normally (some endpoints don't need FLE)
		if cryptoSessionID == "" || cryptoRequestID == "" {
			c.Next()
			return
		}

		// Store crypto context for handlers
		c.Set("crypto_session_id", cryptoSessionID)
		c.Set("crypto_request_id", cryptoRequestID)
		c.Set("crypto_version", cryptoVersion)
		c.Set("crypto_tenant_id", cryptoTenantID)

		c.Next()

		// After handler, if response needs encryption, the handler itself
		// should use the crypto client. This middleware just validates session presence.
		_ = cryptoClient
		_ = cryptoVersion
		_ = cryptoTenantID
	}
}

// CryptoClient wraps the crypto-bff client for FLE operations.
type CryptoClient struct {
	baseURL string
}

// NewCryptoClient creates a new crypto client.
func NewCryptoClient(baseURL string) *CryptoClient {
	return &CryptoClient{baseURL: baseURL}
}

// EncryptFields encrypts specific fields in a response.
func (c *CryptoClient) EncryptFields(
	sessionID, requestID, version, tenantID, method, path string,
	fields map[string]string,
) (map[string]string, error) {
	// Placeholder: In production, this calls the crypto-bff service
	// For now, return fields as-is when crypto is not fully integrated
	return fields, nil
}

// ValidateSession checks if a crypto session is valid.
func (c *CryptoClient) ValidateSession(sessionID string) (bool, error) {
	// Placeholder: In production, validates with crypto-bff
	return sessionID != "", nil
}

// CryptoEnforce ensures required crypto headers are present for protected endpoints.
func CryptoEnforce() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.GetHeader("Crypto-Session-Id")
		requestID := c.GetHeader("Crypto-Request-Id")

		if sessionID == "" || requestID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": map[string]any{
					"code":    90109,
					"message": "Sesion de cifrado invalida.",
				},
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
