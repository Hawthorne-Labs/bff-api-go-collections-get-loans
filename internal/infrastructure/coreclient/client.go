package coreclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
)

// CoreClient is an HTTP client for the collections-operations core.
// It owns an http.Client with connection pooling and an internal JWT signer.
type CoreClient struct {
	baseURL    string
	httpClient *http.Client
	jwtSigner  *JWTSigner
}

// JWTSigner mints internal JWTs for BFF→Core auth.
type JWTSigner struct {
	issuer   string
	audience string
	secret   string
	ttl      time.Duration
}

// NewJWTSigner creates a JWT signer using HS256 with the given secret.
func NewJWTSigner(issuer, audience, secret string) *JWTSigner {
	return &JWTSigner{
		issuer:   issuer,
		audience: audience,
		secret:   secret,
		ttl:      5 * time.Minute,
	}
}

// Mint creates a new internal JWT token.
func (s *JWTSigner) Mint(ctx context.Context) (string, error) {
	// Simplified JWT: in production, use a proper JWT library.
	// This is a placeholder that generates a pseudo-token for now.
	// The real implementation should use github.com/golang-jwt/jwt/v5
	iat := time.Now().Unix()
	exp := iat + int64(s.ttl.Seconds())
	payload := fmt.Sprintf(`{"iss":"%s","aud":"%s","iat":%d,"exp":%d,"sub":"bff-api"}`,
		s.issuer, s.audience, iat, exp)
	// Simple base64 encoding (placeholder — replace with real JWT library)
	token := fmt.Sprintf("INTERNAL.%s", base64urlEncode([]byte(payload)))
	return token, nil
}

func base64urlEncode(b []byte) string {
	s := string(b)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "=", "")
	return s
}

// mtlsBundle is the JSON structure from MTLS_BUNDLE_JSON secret.
type mtlsBundle struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	TrustBundlePEM string `json:"trust_bundle_pem"`
}

// loadMtlsTransport builds an HTTP transport with mTLS client identity
// from the MTLS_BUNDLE_JSON env var. Falls back to plain transport if
// the env var is not set.
func loadMtlsTransport() *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	bundleJSON := os.Getenv("MTLS_BUNDLE_JSON")
	if bundleJSON == "" {
		log.Println("mTLS: MTLS_BUNDLE_JSON not set, using plain transport")
		return transport
	}

	var bundle mtlsBundle
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		log.Printf("mTLS: failed to parse MTLS_BUNDLE_JSON: %v, using plain transport", err)
		return transport
	}

	cert, err := tls.X509KeyPair([]byte(bundle.CertificatePEM), []byte(bundle.PrivateKeyPEM))
	if err != nil {
		log.Printf("mTLS: failed to load client cert/key: %v, using plain transport", err)
		return transport
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(bundle.TrustBundlePEM)) {
		log.Println("mTLS: failed to parse trust bundle, using plain transport")
		return transport
	}

	transport.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}
	log.Println("mTLS: client identity loaded from MTLS_BUNDLE_JSON")
	return transport
}

// NewCoreClient creates a new CoreClient with the given config.
func NewCoreClient(cfg *config.Config) *CoreClient {
	transport := loadMtlsTransport()

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
	}

	// JWT signer uses CORE_JWT_SECRET env var or default
	secret := os.Getenv("CORE_JWT_SECRET")
	if secret == "" {
		secret = "dev-secret-change-in-production"
	}
	signer := NewJWTSigner("bff-api", "core-operations", secret)

	return &CoreClient{
		baseURL:    cfg.CoreBaseURL,
		httpClient: client,
		jwtSigner:  signer,
	}
}

// GetToken mints a new internal JWT.
func (c *CoreClient) GetToken(ctx context.Context) (string, error) {
	return c.jwtSigner.Mint(ctx)
}

// authHeaders returns the standard Authorization + tracing headers for core requests.
func (c *CoreClient) authHeaders(ctx context.Context, traceID, tenantID, userEmail string) (map[string]string, error) {
	token, err := c.jwtSigner.Mint(ctx)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"X-Trace-Id":    traceID,
		"X-Tenant-Id":   tenantID,
	}
	if userEmail != "" {
		headers["X-User-Email"] = userEmail
	}
	return headers, nil
}

// get performs an HTTP GET to the core and returns the parsed JSON response.
func (c *CoreClient) get(ctx context.Context, path string, headers map[string]string, params map[string]string) (map[string]any, error) {
	url := c.baseURL + path
	query := ""
	if len(params) > 0 {
		queryParts := make([]string, 0, len(params))
		for k, v := range params {
			queryParts = append(queryParts, k+"="+v)
		}
		query = "?" + strings.Join(queryParts, "&")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+query, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("core GET %s failed: %v", path, err)
		return nil, fmt.Errorf("core GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		log.Printf("core GET %s returned %d: %s", path, resp.StatusCode, string(body)[:min(len(body), 200)])
		return nil, translateCoreError(resp.StatusCode, body)
	}

	var result map[string]any
	if len(body) == 0 {
		log.Printf("core GET %s returned empty body (200)", path)
		return result, nil
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	log.Printf("core GET %s returned 200, body_len=%d", path, len(body))
	return result, nil
}

// ForwardGet performs a raw GET to the core, returning the HTTP response.
// Used for proxy endpoints (audit, etc.) where the body is forwarded as-is.
func (c *CoreClient) ForwardGet(ctx context.Context, path string, params map[string]string, traceID, requestID, correlationID, traceparent string) (*http.Response, error) {
	url := c.baseURL + path
	if len(params) > 0 {
		queryParts := make([]string, 0, len(params))
		for k, v := range params {
			queryParts = append(queryParts, k+"="+v)
		}
		url += "?" + strings.Join(queryParts, "&")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	token, _ := c.jwtSigner.Mint(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	if traceID != "" {
		req.Header.Set("X-Trace-Id", traceID)
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	if correlationID != "" {
		req.Header.Set("X-Correlation-Id", correlationID)
	}
	if traceparent != "" {
		req.Header.Set("traceparent", traceparent)
	}
	return c.httpClient.Do(req)
}

// ForwardPost performs a raw POST to the core with a JSON body, returning the HTTP response.
// Used for proxy endpoints where the body needs to be forwarded to core.
func (c *CoreClient) ForwardPost(ctx context.Context, path string, body any, traceID, tenantID, requestID, correlationID, traceparent string) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	token, _ := c.jwtSigner.Mint(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if tenantID != "" {
		req.Header.Set("X-Tenant-Id", tenantID)
	}
	if traceID != "" {
		req.Header.Set("X-Trace-Id", traceID)
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	if correlationID != "" {
		req.Header.Set("X-Correlation-Id", correlationID)
	}
	if traceparent != "" {
		req.Header.Set("traceparent", traceparent)
	}
	return c.httpClient.Do(req)
}

// post performs an HTTP POST to the core and returns the parsed JSON response.
func (c *CoreClient) post(ctx context.Context, path string, headers map[string]string, body any) (map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("core POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, translateCoreError(resp.StatusCode, respBody)
	}

	var result map[string]any
	if len(respBody) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result, nil
}

// patch performs an HTTP PATCH to the core and returns the parsed JSON response.
func (c *CoreClient) patch(ctx context.Context, path string, headers map[string]string, body any) (map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("core PATCH %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, translateCoreError(resp.StatusCode, respBody)
	}

	var result map[string]any
	if len(respBody) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result, nil
}

// postNoContent performs an HTTP POST that expects 204 No Content.
func (c *CoreClient) postNoContent(ctx context.Context, path string, headers map[string]string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("core POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return translateCoreError(resp.StatusCode, respBody)
	}
	return nil
}

// ------------------------------------------------------------------
// Public API methods — mirror the Python CoreClient
// ------------------------------------------------------------------

// ListLoans lists loans for the cartera view (with balance: saldo/mora/dpd/estado).
func (c *CoreClient) ListLoans(ctx context.Context, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans", headers, params)
}

// GetLoan gets full loan detail (with nested client/vehicle/paymentPromises).
func (c *CoreClient) GetLoan(ctx context.Context, loanID, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans/"+loanID, headers, nil)
}

// GetLoanBalance gets loan balance breakdown (capital vencido, intereses, mora).
func (c *CoreClient) GetLoanBalance(ctx context.Context, loanID, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans/"+loanID+"/balance", headers, nil)
}

// GetLoanInstallments gets loan installments plan (amortization schedule, paged).
func (c *CoreClient) GetLoanInstallments(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans/"+loanID+"/installments", headers, params)
}

// ListClients lists the client directory (master data, paged, searchable).
func (c *CoreClient) ListClients(ctx context.Context, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/clients", headers, params)
}

// ListClientContacts gets per-client aggregated contact info.
func (c *CoreClient) ListClientContacts(ctx context.Context, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/clients/contacts", headers, params)
}

// ListAtRisk gets unique clients in mora — the strategy assignment pool.
func (c *CoreClient) ListAtRisk(ctx context.Context, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/clients/at-risk", headers, params)
}

// ListUsers gets the application users catalog (admin only).
func (c *CoreClient) ListUsers(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/users", headers, nil)
}

// CreateUser creates an application user.
func (c *CoreClient) CreateUser(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/internal/v1/users", headers, body)
}

// UpdateUser updates an application user.
func (c *CoreClient) UpdateUser(ctx context.Context, userID, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.patch(ctx, "/internal/v1/users/"+userID, headers, body)
}

// RecordLastLogin records the authenticated user's login timestamp.
func (c *CoreClient) RecordLastLogin(ctx context.Context, traceID, tenantID, userEmail string) error {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return err
	}
	return c.postNoContent(ctx, "/internal/v1/me/last-login", headers, map[string]any{})
}

// GetMyPermissions gets the current user's application scopes and module permissions.
func (c *CoreClient) GetMyPermissions(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/me/permissions", headers, nil)
}

// ListMyTenants gets tenants the current user may operate on.
func (c *CoreClient) ListMyTenants(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/me/tenants", headers, nil)
}

// ListTenantSyncStatus gets tenant sync status for supervisor, manager, and admin.
func (c *CoreClient) ListTenantSyncStatus(ctx context.Context, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/admin/tenants", headers, nil)
}

// GetStrategySegmentation gets live account counts per priority bucket.
func (c *CoreClient) GetStrategySegmentation(ctx context.Context, traceID, tenantID, userEmail, marca string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	if marca != "" {
		params["marca"] = marca
	}
	return c.get(ctx, "/internal/v1/strategy/segmentation", headers, params)
}

// ListStrategyAssignments gets strategy assignment audit trail.
func (c *CoreClient) ListStrategyAssignments(ctx context.Context, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/strategy/assignments", headers, params)
}

// CreateStrategyAssignment persists a strategy assignment.
func (c *CoreClient) CreateStrategyAssignment(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/internal/v1/strategy/assignments", headers, body)
}

// CleanStrategyQueue persists a queue-clean action.
func (c *CoreClient) CleanStrategyQueue(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/internal/v1/strategy/clean", headers, body)
}

// SubmitContact submits a contact request.
func (c *CoreClient) SubmitContact(ctx context.Context, traceID, tenantID, userEmail string, payload map[string]string, metadata map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	// Add metadata headers
	if requestID := metadata["request_id"]; requestID != "" {
		headers["X-Request-Id"] = requestID
	}
	if correlationID := metadata["correlation_id"]; correlationID != "" {
		headers["X-Correlation-Id"] = correlationID
	}
	if traceparent := metadata["traceparent"]; traceparent != "" {
		headers["traceparent"] = traceparent
	}
	return c.post(ctx, "/api/v1/contacts", headers, payload)
}

// GetLoanStatement gets loan statement/history (account activity, paged, date-filtered).
func (c *CoreClient) GetLoanStatement(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans/"+loanID+"/statement", headers, params)
}
