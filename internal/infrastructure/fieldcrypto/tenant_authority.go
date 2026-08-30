package fieldcrypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/security"
)

var (
	forbiddenSelectors = map[string]struct{}{
		"": {}, "default": {}, "all": {}, "*": {}, "null": {}, "none": {}, "undefined": {}, "anonymous": {},
	}
	devDigestKey = "dev-crypto-tenant-digest-key-32bytes!"
)

// AuthorizedTenantContext holds authorized tenant digest.
type AuthorizedTenantContext struct {
	TenantID     string
	TenantDigest string
}

// TenantAuthority resolves tenant digest for crypto sessions.
type TenantAuthority interface {
	Resolve(ctx context.Context, authorization, tenantSelector, userEmail string, consultCore bool, traceID string) (*AuthorizedTenantContext, error)
}

// ComputeTenantDigest computes HMAC-SHA256(namespace|tenant_id).
func ComputeTenantDigest(digestKey []byte, namespace, tenantID string) string {
	message := fmt.Sprintf("%s|%s", strings.TrimSpace(namespace), strings.TrimSpace(tenantID))
	mac := hmac.New(sha256.New, digestKey)
	mac.Write([]byte(message))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// TenantDigestKeyFromEnv loads CRYPTO_TENANT_DIGEST_KEY.
func TenantDigestKeyFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("CRYPTO_TENANT_DIGEST_KEY"))
	if raw != "" {
		if SessionModeFromEnv() == "stateless" {
			secret, err := AssertSigningOrDigestSecretNotWeak("CRYPTO_TENANT_DIGEST_KEY", raw)
			if err != nil {
				return nil, err
			}
			return []byte(secret), nil
		}
		if len(raw) < 32 {
			return nil, fmt.Errorf("CRYPTO_TENANT_DIGEST_KEY must be at least 32 bytes")
		}
		return []byte(raw), nil
	}
	if SessionModeFromEnv() == "stateless" {
		return nil, fmt.Errorf("CRYPTO_TENANT_DIGEST_KEY must be set when CRYPTO_SESSION_MODE=stateless")
	}
	if isLocalOrTestEnvironment() {
		return []byte(devDigestKey), nil
	}
	return nil, fmt.Errorf("CRYPTO_TENANT_DIGEST_KEY must be set explicitly outside local/test environments")
}

// ManagementTenantClient calls Core management /internal/v1/me/tenants.
type ManagementTenantClient struct {
	baseURL   string
	signer    *security.InternalJWTSigner
	audience  string
	subject   string
	httpClient *http.Client
}

// NewManagementTenantClient creates a management tenant client.
func NewManagementTenantClient(baseURL, secret, issuer, kid, audience string, timeout time.Duration, httpClient *http.Client) *ManagementTenantClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &ManagementTenantClient{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		signer:     security.NewInternalJWTSigner(secret, issuer, kid, timeout),
		audience:   audience,
		subject:    "bff-api",
		httpClient: httpClient,
	}
}

// ManagementTenantClientFromEnv builds client from env.
func ManagementTenantClientFromEnv(httpClient *http.Client) (*ManagementTenantClient, error) {
	baseURL := strings.TrimSpace(os.Getenv("MANAGEMENT_CORE_API_BASE_URL"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("IDENTITY_CORE_API_BASE_URL"))
	}
	if baseURL == "" {
		return nil, fmt.Errorf("MANAGEMENT_CORE_API_BASE_URL (or IDENTITY_CORE_API_BASE_URL) must be set for crypto TenantAuthority")
	}
	secret := strings.TrimSpace(os.Getenv("INTERNAL_JWT_SECRET"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("CORE_INTERNAL_TOKEN"))
	}
	if secret == "" {
		secret = "dev-internal-jwt-secret-32-bytes-min"
	}
	issuer := getEnvDefault("INTERNAL_JWT_ISSUER", "python-templates-finch")
	kid := strings.TrimSpace(os.Getenv("INTERNAL_JWT_ACTIVE_KID"))
	audience := getEnvDefault("INTERNAL_JWT_CORE_AUDIENCE", "core-api")
	timeout := 5 * time.Second
	if v := strings.TrimSpace(os.Getenv("MANAGEMENT_CORE_TIMEOUT_SECONDS")); v != "" {
		if f, err := parseFloat(v); err == nil {
			timeout = time.Duration(f * float64(time.Second))
		}
	}
	return NewManagementTenantClient(baseURL, secret, issuer, kid, audience, timeout, httpClient), nil
}

func parseFloat(v string) (float64, error) {
	return strconv.ParseFloat(v, 64)
}

// AuthorizedTenants returns allowed tenant ids for an email.
func (c *ManagementTenantClient) AuthorizedTenants(ctx context.Context, email, traceID string) ([]string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, NewSessionInvalid()
	}
	token, err := c.signer.Mint(c.audience, c.subject, email)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/v1/me/tenants", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-User-Email", email)
	if traceID == "" {
		traceID = "-"
	}
	req.Header.Set("X-Trace-Id", traceID)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, NewTenantAuthorityUnavailable()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 500 {
		return nil, NewTenantAuthorityUnavailable()
	}
	if resp.StatusCode >= 400 {
		return nil, NewSessionInvalid()
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, NewSessionInvalid()
	}
	return parseTenantIDs(payload)
}

func parseTenantIDs(payload map[string]any) ([]string, error) {
	items, ok := payload["items"].([]any)
	if !ok {
		return nil, NewSessionInvalid()
	}
	if len(items) > 256 {
		return nil, NewSessionInvalid()
	}
	tenantIDs := make([]string, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, NewSessionInvalid()
		}
		tenantID, ok := obj["id"].(string)
		if !ok || len(strings.TrimSpace(tenantID)) < 1 || len(strings.TrimSpace(tenantID)) > 64 {
			return nil, NewSessionInvalid()
		}
		tenantIDs = append(tenantIDs, strings.TrimSpace(tenantID))
	}
	return tenantIDs, nil
}

// CoreManagementTenantAuthority authorizes tenant via Core management.
type CoreManagementTenantAuthority struct {
	client     *ManagementTenantClient
	digestKey  []byte
	namespace  string
}

// NewCoreManagementTenantAuthority creates tenant authority.
func NewCoreManagementTenantAuthority(client *ManagementTenantClient, digestKey []byte, namespace string) *CoreManagementTenantAuthority {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "get-loans"
	}
	return &CoreManagementTenantAuthority{client: client, digestKey: digestKey, namespace: ns}
}

func (a *CoreManagementTenantAuthority) Resolve(
	ctx context.Context,
	authorization, tenantSelector, userEmail string,
	consultCore bool,
	traceID string,
) (*AuthorizedTenantContext, error) {
	if strings.TrimSpace(authorization) == "" {
		return nil, NewSessionInvalid()
	}
	selector, err := normalizeSelector(tenantSelector)
	if err != nil {
		return nil, err
	}
	if consultCore {
		email := strings.TrimSpace(userEmail)
		if email == "" {
			return nil, NewSessionInvalid()
		}
		allowed, err := a.client.AuthorizedTenants(ctx, email, traceID)
		if err != nil {
			return nil, err
		}
		found := false
		for _, id := range allowed {
			if id == selector {
				found = true
				break
			}
		}
		if !found {
			return nil, NewSessionInvalid()
		}
	}
	digest := ComputeTenantDigest(a.digestKey, a.namespace, selector)
	return &AuthorizedTenantContext{TenantID: selector, TenantDigest: digest}, nil
}

func normalizeSelector(tenantSelector string) (string, error) {
	selector := strings.TrimSpace(tenantSelector)
	if _, bad := forbiddenSelectors[strings.ToLower(selector)]; bad {
		return "", NewSessionInvalid()
	}
	return selector, nil
}

// StaticTenantAuthority is injectable authority for tests.
type StaticTenantAuthority struct {
	tenantID string
	digest   string
}

// NewStaticTenantAuthority creates static authority.
func NewStaticTenantAuthority(tenantID, tenantDigest string) (*StaticTenantAuthority, error) {
	digest, err := assertTenantDigestExplicit(tenantDigest)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(tenantID)
	if _, bad := forbiddenSelectors[strings.ToLower(id)]; bad {
		return nil, fmt.Errorf("tenant_id must be an explicit authorized tenant")
	}
	return &StaticTenantAuthority{tenantID: id, digest: digest}, nil
}

func (a *StaticTenantAuthority) Resolve(
	ctx context.Context,
	authorization, tenantSelector, userEmail string,
	consultCore bool,
	traceID string,
) (*AuthorizedTenantContext, error) {
	_ = ctx
	_ = userEmail
	_ = consultCore
	_ = traceID
	if strings.TrimSpace(authorization) == "" {
		return nil, NewSessionInvalid()
	}
	selector, err := normalizeSelector(tenantSelector)
	if err != nil {
		return nil, err
	}
	if selector != a.tenantID {
		return nil, NewSessionInvalid()
	}
	return &AuthorizedTenantContext{TenantID: a.tenantID, TenantDigest: a.digest}, nil
}

// FailClosedTenantAuthority rejects all requests.
type FailClosedTenantAuthority struct{}

func (FailClosedTenantAuthority) Resolve(context.Context, string, string, string, bool, string) (*AuthorizedTenantContext, error) {
	return nil, NewSessionInvalid()
}

var globalTenantAuthority TenantAuthority = FailClosedTenantAuthority{}

// GetTenantAuthority returns global tenant authority.
func GetTenantAuthority() TenantAuthority { return globalTenantAuthority }

// SetTenantAuthority sets global tenant authority.
func SetTenantAuthority(authority TenantAuthority) { globalTenantAuthority = authority }

// ResetTenantAuthorityForTests resets tenant authority.
func ResetTenantAuthorityForTests() { globalTenantAuthority = FailClosedTenantAuthority{} }

// BuildTenantAuthorityFromEnv builds CoreManagementTenantAuthority.
func BuildTenantAuthorityFromEnv(client *ManagementTenantClient) (TenantAuthority, error) {
	digestKey, err := TenantDigestKeyFromEnv()
	if err != nil {
		return nil, err
	}
	if client == nil {
		var err error
		client, err = ManagementTenantClientFromEnv(nil)
		if err != nil {
			return nil, err
		}
	}
	namespace := getEnvDefault("CRYPTO_SESSION_NAMESPACE", "get-loans")
	return NewCoreManagementTenantAuthority(client, digestKey, namespace), nil
}
