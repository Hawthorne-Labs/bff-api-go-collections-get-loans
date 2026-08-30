package coreclient

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
)

// Guard: CoreClient must mint real HS256 JWTs (aud=core-api), not the INTERNAL.* stub
// that caused prod login 502 via Core UNAUTHORIZED_INTERNAL on /me/permissions.
func TestNewCoreClientAuthHeadersMintRealHS256JWT(t *testing.T) {
	const secret = "dev-internal-jwt-secret-32-bytes-min"
	cfg := &config.Config{
		CoreBaseURL:             "http://localhost:9090",
		RequestTimeoutSeconds:   1,
		InternalJWTSecret:       secret,
		InternalJWTIssuer:       "python-templates-finch",
		InternalJWTCoreAudience: "core-api",
	}

	client := NewCoreClient(cfg)
	headers, err := client.authHeaders(t.Context(), "trace-1", "tenant-1", "Agent@Example.com")
	if err != nil {
		t.Fatalf("authHeaders: %v", err)
	}

	auth := headers["Authorization"]
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("missing Bearer prefix: %q", auth)
	}
	tokenString := strings.TrimPrefix(auth, "Bearer ")
	if strings.HasPrefix(tokenString, "INTERNAL.") {
		t.Fatalf("stub INTERNAL. token must not be minted for Core")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			t.Fatalf("unexpected alg: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithIssuer("python-templates-finch"), jwt.WithAudience("core-api"))
	if err != nil {
		t.Fatalf("parse minted JWT: %v", err)
	}
	if !token.Valid {
		t.Fatal("expected valid JWT")
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["actor_email"] != "agent@example.com" {
		t.Fatalf("actor_email: %v", claims["actor_email"])
	}
	if headers["X-User-Email"] != "Agent@Example.com" {
		t.Fatalf("X-User-Email: %q", headers["X-User-Email"])
	}
}
