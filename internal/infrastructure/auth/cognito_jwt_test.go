package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
)

type fakeEmailLookup struct {
	emails   map[string]string
	calls    []string
	failures int
}

func (f *fakeEmailLookup) LookupEmail(_ context.Context, username string) (string, bool, error) {
	f.calls = append(f.calls, username)
	if f.failures > 0 {
		f.failures--
		return "", false, errLookupTransient
	}
	email, ok := f.emails[username]
	if !ok {
		return "", true, nil
	}
	return email, false, nil
}

var errLookupTransient = errString("transient cognito error")

type errString string

func (e errString) Error() string { return string(e) }

func testRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return key
}

func jwksJSON(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	body, err := json.Marshal(jwkDocument{Keys: []jwkKey{{
		Kid: kid,
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

func mintAccessToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "http://issuer.example/pool"
	}
	if _, ok := claims["sub"]; !ok {
		claims["sub"] = "user-123"
	}
	if _, ok := claims["token_use"]; !ok {
		claims["token_use"] = "access"
	}
	if _, ok := claims["client_id"]; !ok {
		claims["client_id"] = "spa-client"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func testValidator(t *testing.T, key *rsa.PrivateKey, lookup EmailLookup, cache IdentityEmailCache) *CognitoJwtValidator {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, "test-key", &key.PublicKey))
	}))
	t.Cleanup(server.Close)
	return NewCognitoJwtValidator(&config.Config{
		CognitoIssuer:   "http://issuer.example/pool",
		CognitoAudience: "spa-client",
		CognitoJWKSURL:  server.URL,
		CognitoPoolID:   "pool-id",
		AWSRegion:       "us-east-2",
	}, lookup, cache)
}

func TestValidAccessTokenUsesEmailClaim(t *testing.T) {
	key := testRSA(t)
	validator := testValidator(t, key, nil, nil)
	token := mintAccessToken(t, key, "test-key", jwt.MapClaims{
		"email":           "agent1@hawthorne.local",
		"cognito:groups":  []string{"agent"},
	})
	claims, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Email != "agent1@hawthorne.local" || claims.Role != "agent" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if _, ok := claims.Scopes["collections:read"]; !ok {
		t.Fatal("expected collections:read scope")
	}
}

func TestRejectsWrongAudience(t *testing.T) {
	key := testRSA(t)
	validator := testValidator(t, key, nil, nil)
	token := mintAccessToken(t, key, "test-key", jwt.MapClaims{"client_id": "other-client"})
	if _, err := validator.Validate(context.Background(), token); err == nil {
		t.Fatal("expected invalid token")
	}
}

func TestAccessTokenWithoutEmailUsesAdminGetUser(t *testing.T) {
	key := testRSA(t)
	lookup := &fakeEmailLookup{emails: map[string]string{"user-123": "real.user@dev.io"}}
	validator := testValidator(t, key, lookup, NewInMemoryTtlIdentityEmailCache())
	token := mintAccessToken(t, key, "test-key", jwt.MapClaims{})
	claims, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Email != "real.user@dev.io" {
		t.Fatalf("expected lookup email, got %q", claims.Email)
	}
	if len(lookup.calls) != 1 {
		t.Fatalf("expected one lookup, got %v", lookup.calls)
	}
}

func TestAdminGetUserResultIsCached(t *testing.T) {
	key := testRSA(t)
	lookup := &fakeEmailLookup{emails: map[string]string{"user-123": "real.user@dev.io"}}
	validator := testValidator(t, key, lookup, NewInMemoryTtlIdentityEmailCache())
	token := mintAccessToken(t, key, "test-key", jwt.MapClaims{})
	_, _ = validator.Validate(context.Background(), token)
	_, _ = validator.Validate(context.Background(), token)
	if len(lookup.calls) != 1 {
		t.Fatalf("expected cached lookup, got %v", lookup.calls)
	}
}

func TestFailedAdminGetUserIsNotCached(t *testing.T) {
	// anti-regresion: BUG-0662 ver handoffs/regressions.md (no revertir sin leer)
	key := testRSA(t)
	lookup := &fakeEmailLookup{emails: map[string]string{"user-123": "real.user@dev.io"}, failures: 1}
	validator := testValidator(t, key, lookup, NewInMemoryTtlIdentityEmailCache())
	token := mintAccessToken(t, key, "test-key", jwt.MapClaims{})
	failed, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if failed.Email != "" {
		t.Fatalf("expected empty email after failure, got %q", failed.Email)
	}
	recovered, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate retry: %v", err)
	}
	if recovered.Email != "real.user@dev.io" {
		t.Fatalf("expected recovered email, got %q", recovered.Email)
	}
	if len(lookup.calls) != 2 {
		t.Fatalf("expected retry after failure, got %v", lookup.calls)
	}
}

func TestCognitoGroupsAcceptsCommaSeparatedString(t *testing.T) {
	key := testRSA(t)
	validator := testValidator(t, key, nil, nil)
	token := mintAccessToken(t, key, "test-key", jwt.MapClaims{
		"email":          "agent1@hawthorne.local",
		"cognito:groups": "supervisor,agent",
	})
	claims, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Role != "supervisor" {
		t.Fatalf("expected supervisor from string groups, got %+v", claims)
	}
}

func TestEmptyEmailIsNeverCached(t *testing.T) {
	cache := NewInMemoryTtlIdentityEmailCache()
	cache.Set("user-123", "")
	if cache.Get("user-123") != "" {
		t.Fatal("empty emails must not be stored")
	}
}
