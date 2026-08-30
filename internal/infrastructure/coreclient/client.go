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
	"net/url"
	"os"
	"time"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/security"
)

// CoreClient is an HTTP client for the collections-management core.
// It owns an http.Client with connection pooling and an internal JWT signer.
type CoreClient struct {
	baseURL    string
	httpClient *http.Client
	jwtSigner  *security.InternalJWTSigner
	audience   string
	subject    string
}

// NewMtlsHTTPClient returns an HTTP client using the task mTLS bundle when present.
func NewMtlsHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Transport: loadMtlsTransport(),
		Timeout:   timeout,
	}
}

// NewCoreClient creates a new CoreClient with the given config.
func NewCoreClient(cfg *config.Config) *CoreClient {
	client := NewMtlsHTTPClient(time.Duration(cfg.RequestTimeoutSeconds) * time.Second)

	// anti-regresion: BUG-1006 ver handoffs/regressions.md (no revertir sin leer)
	secret := cfg.InternalJWTSecret
	issuer := cfg.InternalJWTIssuer
	audience := cfg.InternalJWTCoreAudience
	signer := security.NewInternalJWTSigner(secret, issuer, cfg.InternalJWTActiveKID, 5*time.Minute)

	return &CoreClient{
		baseURL:    cfg.CoreBaseURL,
		httpClient: client,
		jwtSigner:  signer,
		audience:   audience,
		subject:    "bff-api",
	}
}

// GetToken mints a new internal JWT without actor scope.
func (c *CoreClient) GetToken(_ context.Context) (string, error) {
	return c.jwtSigner.Mint(c.audience, c.subject, "")
}

// authHeaders returns the standard Authorization + tracing headers for core requests.
func (c *CoreClient) authHeaders(_ context.Context, traceID, tenantID, userEmail string) (map[string]string, error) {
	token, err := c.jwtSigner.Mint(c.audience, c.subject, userEmail)
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

// encodeQuery builds a stable, percent-encoded query string.
// anti-regresion: BUG-1010 — raw concat broke phone search with spaces (+504 9xxx) → Core 400 → BFF 502.
func encodeQuery(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return "?" + values.Encode()
}

// get performs an HTTP GET to the core and returns the parsed JSON response.
func (c *CoreClient) get(ctx context.Context, path string, headers map[string]string, params map[string]string) (map[string]any, error) {
	reqURL := c.baseURL + path + encodeQuery(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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
	reqURL := c.baseURL + path + encodeQuery(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	token, err := c.jwtSigner.Mint(c.audience, c.subject, "")
	if err != nil {
		return nil, fmt.Errorf("mint internal jwt: %w", err)
	}
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
	token, err := c.jwtSigner.Mint(c.audience, c.subject, "")
	if err != nil {
		return nil, fmt.Errorf("mint internal jwt: %w", err)
	}
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
	return c.writeJSON(ctx, http.MethodPatch, path, headers, body)
}

// put performs an HTTP PUT to the core and returns the parsed JSON response.
func (c *CoreClient) put(ctx context.Context, path string, headers map[string]string, body any) (map[string]any, error) {
	return c.writeJSON(ctx, http.MethodPut, path, headers, body)
}

func (c *CoreClient) writeJSON(ctx context.Context, method, path string, headers map[string]string, body any) (map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("core %s %s: %w", method, path, err)
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
func (c *CoreClient) GetLoan(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans/"+loanID, headers, params)
}

// GetLoanBalance gets loan balance breakdown (capital vencido, intereses, mora).
func (c *CoreClient) GetLoanBalance(ctx context.Context, loanID, traceID, tenantID, userEmail string, params map[string]string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/loans/"+loanID+"/balance", headers, params)
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

// ListRoles lists application roles (admin).
func (c *CoreClient) ListRoles(ctx context.Context, traceID, tenantID, userEmail string, activeOnly bool) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	if activeOnly {
		params["active"] = "true"
	}
	return c.get(ctx, "/internal/v1/roles", headers, params)
}

// GetRole gets one application role by code (admin).
func (c *CoreClient) GetRole(ctx context.Context, code, traceID, tenantID, userEmail string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.get(ctx, "/internal/v1/roles/"+code, headers, nil)
}

// CreateRole creates an application role (admin).
func (c *CoreClient) CreateRole(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/internal/v1/roles", headers, body)
}

// UpdateRole patches an application role (admin).
func (c *CoreClient) UpdateRole(ctx context.Context, code, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.patch(ctx, "/internal/v1/roles/"+code, headers, body)
}

// ReplaceRolePermissions replaces the permission set for a role (admin).
func (c *CoreClient) ReplaceRolePermissions(ctx context.Context, code, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	return c.put(ctx, "/internal/v1/roles/"+code+"/permissions", headers, body)
}

// ListPermissions lists the permission catalog (admin).
func (c *CoreClient) ListPermissions(ctx context.Context, traceID, tenantID, userEmail, module string) (map[string]any, error) {
	headers, err := c.authHeaders(ctx, traceID, tenantID, userEmail)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	if module != "" {
		params["module"] = module
	}
	return c.get(ctx, "/internal/v1/permissions", headers, params)
}
