package cryptobffclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
)

// CryptoBFFClient handles Field-Level Encryption (FLE) operations
// by proxying to the crypto-bff service.
type CryptoBFFClient struct {
	baseURL    string
	httpClient *http.Client
}

// EncryptRequest represents a field-level encryption request.
type EncryptRequest struct {
	CryptoVersion   string            `json:"crypto_version"`
	CryptoSessionID string            `json:"crypto_session_id"`
	CryptoRequestID string            `json:"crypto_request_id"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	CryptoTenantID  string            `json:"crypto_tenant_id"`
	PlaintextFields map[string]string `json:"plaintext_fields"`
}

// EncryptResponse represents the encrypted result.
type EncryptResponse struct {
	EncryptedFields map[string]string `json:"encrypted_fields"`
}

// NewCryptoBFFClient creates a new client for the crypto-bff service.
func NewCryptoBFFClient(cfg *config.Config) *CryptoBFFClient {
	return &CryptoBFFClient{
		baseURL: cfg.CryptoBFFBaseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// EncryptFields encrypts specific fields in a response using FLE.
// Returns the encrypted fields and sets response headers for the client.
func (c *CryptoBFFClient) EncryptFields(
	ctx context.Context,
	req EncryptRequest,
) (*EncryptResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypt request: %w", err)
	}

	resp, err := c.httpClient.Do(http.NewRequestWithContext(
		ctx, http.MethodPost, c.baseURL+"/api/v1/crypto/encrypt", bytes.NewReader(payload),
	))
	if err != nil {
		return nil, fmt.Errorf("crypto-bff encrypt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("crypto-bff encrypt status %d: %s", resp.StatusCode, string(body))
	}

	var result EncryptResponse
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("parse encrypt response: %w", err)
	}
	return &result, nil
}

// CreateSession creates a new crypto session for FLE.
func (c *CryptoBFFClient) CreateSession(
	ctx context.Context,
	tenantID string,
) (map[string]any, error) {
	resp, err := c.httpClient.Do(http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.baseURL+"/api/v1/crypto-sessions", nil,
	))
	if err != nil {
		return nil, fmt.Errorf("crypto-bff create session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("crypto-bff create session status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("parse session response: %w", err)
	}
	return result, nil
}
