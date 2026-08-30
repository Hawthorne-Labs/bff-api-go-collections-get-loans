package security

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestInternalJWTSignerMintsHS256TokenForCore(t *testing.T) {
	const secret = "dev-internal-jwt-secret-32-bytes-min"
	signer := NewInternalJWTSigner(secret, "python-templates-finch", "", time.Minute)

	tokenString, err := signer.Mint("core-api", "bff-api", "Agent@Example.com")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	if strings.HasPrefix(tokenString, "INTERNAL.") {
		t.Fatalf("stub INTERNAL. token must not be used: %s", tokenString[:min(40, len(tokenString))])
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithIssuer("python-templates-finch"), jwt.WithAudience("core-api"))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !token.Valid {
		t.Fatal("expected valid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected map claims")
	}
	if claims["sub"] != "bff-api" {
		t.Fatalf("unexpected sub: %v", claims["sub"])
	}
	if claims["actor_email"] != "agent@example.com" {
		t.Fatalf("unexpected actor_email: %v", claims["actor_email"])
	}
}
