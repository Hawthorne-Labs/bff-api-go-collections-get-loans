package security

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// InternalJWTSigner mints HS256 internal JWTs compatible with Core Management
// and core-operations (same contract as the Python BFF InternalJWTSigner).
type InternalJWTSigner struct {
	secret string
	issuer string
	kid    string
	ttl    time.Duration
}

// NewInternalJWTSigner creates a signer using the shared internal JWT secret.
func NewInternalJWTSigner(secret, issuer, kid string, ttl time.Duration) *InternalJWTSigner {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &InternalJWTSigner{
		secret: secret,
		issuer: issuer,
		kid:    strings.TrimSpace(kid),
		ttl:    ttl,
	}
}

type internalClaims struct {
	ActorEmail string `json:"actor_email,omitempty"`
	jwt.RegisteredClaims
}

// Mint signs a short-lived service JWT for BFF-to-Core calls.
func (s *InternalJWTSigner) Mint(audience, subject, actorEmail string) (string, error) {
	now := time.Now()
	claims := internalClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	if trimmed := strings.TrimSpace(actorEmail); trimmed != "" {
		claims.ActorEmail = strings.ToLower(trimmed)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if s.kid != "" {
		token.Header["kid"] = s.kid
	}
	return token.SignedString([]byte(s.secret))
}
