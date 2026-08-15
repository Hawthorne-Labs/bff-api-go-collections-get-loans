package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/cryptobffclient"
)

// ContactsHandler handles contact submission endpoints.
type ContactsHandler struct {
	core      *coreclient.CoreClient
	cryptoBff *cryptobffclient.CryptoBFFClient
}

// NewContactsHandler creates a new ContactsHandler.
func NewContactsHandler(core *coreclient.CoreClient, cryptoBff *cryptobffclient.CryptoBFFClient) *ContactsHandler {
	return &ContactsHandler{core: core, cryptoBff: cryptoBff}
}

// SubmitContact handles POST /api/v1/contacts
// Receives FLE-encrypted payload, decrypts, validates, and forwards to Core.
func (h *ContactsHandler) SubmitContact(c *gin.Context) {
	// Read FLE headers
	cryptoVersion := c.GetHeader("Crypto-Version")
	cryptoSessionID := c.GetHeader("Crypto-Session-Id")
	cryptoRequestID := c.GetHeader("Crypto-Request-Id")
	cryptoTimestamp := c.GetHeader("Crypto-Timestamp")
	cryptoTenantID := c.GetHeader("Crypto-Tenant-Id")
	if cryptoTenantID == "" {
		cryptoTenantID = "default"
	}

	if cryptoVersion == "" || cryptoSessionID == "" || cryptoRequestID == "" || cryptoTimestamp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": 90100, "message": "Faltan headers de cifrado."}})
		return
	}

	// Read body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": 90100, "message": "Body invalido."}})
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": 90100, "message": "JSON invalido."}})
		return
	}

	// Extract encrypted fields
	encryptedFields := make(map[string]string)
	requiredFields := []string{"name", "email", "message"}
	for _, field := range requiredFields {
		val, ok := payload[field]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": 90100, "message": fmt.Sprintf("Campo cifrado requerido faltante: %s", field)}})
			return
		}
		strVal, ok := val.(string)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": 90100, "message": fmt.Sprintf("Campo %s debe ser string", field)}})
			return
		}
		encryptedFields[field] = strVal
	}

	// Decrypt via crypto-bff
	traceID, _ := c.Get("trace_id")
	requestID, _ := c.Get("request_id")
	correlationID, _ := c.Get("correlation_id")
	traceparent := c.GetHeader("traceparent")

	decryptResp, err := h.cryptoBff.DecryptFields(
		c.Request.Context(),
		cryptoVersion, cryptoSessionID, cryptoRequestID, cryptoTimestamp, cryptoTenantID,
		"POST", "/api/v1/contacts",
		encryptedFields,
		fmt.Sprintf("%v", requestID), fmt.Sprintf("%v", correlationID), traceparent,
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": gin.H{"code": 90101, "message": "No se pudo descifrar el payload."}})
		return
	}

	// Validate plaintext sizes
	plaintext := decryptResp.Plaintext
	if len(plaintext["name"]) > 120 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": gin.H{"code": 90102, "message": "name exceeds 120 chars"}})
		return
	}
	if len(plaintext["email"]) > 254 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": gin.H{"code": 90102, "message": "email exceeds 254 chars"}})
		return
	}
	if len(plaintext["message"]) > 4000 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": gin.H{"code": 90102, "message": "message exceeds 4000 chars"}})
		return
	}

	// Build plaintext payload for Core
	corePayload := map[string]string{
		"name":    plaintext["name"],
		"email":   plaintext["email"],
		"message": plaintext["message"],
	}

	// Forward to Core
	coreResp, err := h.core.ForwardPost(
		c.Request.Context(),
		"/api/v1/contacts",
		corePayload,
		fmt.Sprintf("%v", traceID),
		cryptoTenantID,
		fmt.Sprintf("%v", requestID),
		fmt.Sprintf("%v", correlationID),
		traceparent,
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": gin.H{"code": 90103, "message": "No se pudo enviar la solicitud de contacto."}})
		return
	}
	defer coreResp.Body.Close()

	respBody, _ := io.ReadAll(coreResp.Body)
	c.Data(coreResp.StatusCode, "application/json", respBody)
}
