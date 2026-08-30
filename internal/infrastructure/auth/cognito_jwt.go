package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
)

var ErrInvalidCognitoToken = errors.New("invalid cognito token")

var roleScopes = map[string][]string{
	"agent":       {"collections:read", "collections:write", "collections:read:own", "collections:write:own", "notifications:read", "notifications:write"},
	"call_center": {"collections:read", "collections:write", "collections:read:own", "collections:write:own", "notifications:read", "notifications:write"},
	"supervisor":  {"collections:read", "collections:write", "collections:escalate", "collections:assign", "notifications:read", "notifications:write"},
	"manager":     {"collections:read", "collections:write", "collections:escalate", "collections:assign", "collections:approve", "notifications:read", "notifications:write"},
	"admin":       {"collections:read", "collections:write", "collections:escalate", "collections:assign", "collections:approve", "notifications:read", "notifications:write"},
	"auditor":     {"collections:read"},
}

var rolePriority = []string{"admin", "manager", "supervisor", "call_center", "agent", "auditor"}

type CognitoClaims struct {
	Subject string
	Email   string
	Role    string
	Groups  []string
	Scopes  map[string]struct{}
}

type cognitoAccessClaims struct {
	jwt.RegisteredClaims
	TokenUse string        `json:"token_use"`
	ClientID string        `json:"client_id"`
	Email    string        `json:"email"`
	Scope    string        `json:"scope"`
	Groups   cognitoGroups `json:"cognito:groups"`
}

// cognitoGroups accepts the Python-compatible shapes: JSON array or comma-separated string.
type cognitoGroups []string

func (g *cognitoGroups) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || len(data) == 0 {
		*g = nil
		return nil
	}
	if data[0] == '"' {
		var raw string
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		*g = splitGroups(raw)
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*g = values
	return nil
}

func splitGroups(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

type CognitoJwtValidator struct {
	issuer    string
	audiences map[string]struct{}
	jwks      *jwksCache
	poolID    string
	lookup    EmailLookup
	cache     IdentityEmailCache
}

func NewCognitoJwtValidator(cfg *config.Config, lookup EmailLookup, cache IdentityEmailCache) *CognitoJwtValidator {
	issuer := strings.TrimSpace(cfg.CognitoIssuer)
	if issuer == "" && cfg.AWSRegion != "" && cfg.CognitoPoolID != "" {
		issuer = "https://cognito-idp." + cfg.AWSRegion + ".amazonaws.com/" + cfg.CognitoPoolID
	}
	jwksURL := strings.TrimSpace(cfg.CognitoJWKSURL)
	if jwksURL == "" && issuer != "" {
		jwksURL = issuer + "/.well-known/jwks.json"
	}
	audiences := map[string]struct{}{}
	for _, part := range strings.Split(cfg.CognitoAudience, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			audiences[trimmed] = struct{}{}
		}
	}
	if cache == nil {
		cache = NewInMemoryTtlIdentityEmailCache()
	}
	return &CognitoJwtValidator{
		issuer:    issuer,
		audiences: audiences,
		jwks:      newJWKSCache(jwksURL),
		poolID:    strings.TrimSpace(cfg.CognitoPoolID),
		lookup:    lookup,
		cache:     cache,
	}
}

func (v *CognitoJwtValidator) Validate(ctx context.Context, tokenString string) (CognitoClaims, error) {
	if v == nil || v.issuer == "" || len(v.audiences) == 0 || v.jwks == nil || v.jwks.url == "" {
		return CognitoClaims{}, ErrInvalidCognitoToken
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(v.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	var claims cognitoAccessClaims
	_, err := parser.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, ErrInvalidCognitoToken
		}
		return v.jwks.key(kid)
	})
	if err != nil {
		return CognitoClaims{}, ErrInvalidCognitoToken
	}
	if claims.TokenUse != "access" || strings.TrimSpace(claims.Subject) == "" {
		return CognitoClaims{}, ErrInvalidCognitoToken
	}
	if !v.validAudience(claims) {
		return CognitoClaims{}, ErrInvalidCognitoToken
	}
	groups := normalizeGroups([]string(claims.Groups))
	role := ""
	for _, candidate := range rolePriority {
		if _, ok := groups[candidate]; ok {
			role = candidate
			break
		}
	}
	scopes := map[string]struct{}{}
	for _, scope := range strings.Fields(claims.Scope) {
		scopes[scope] = struct{}{}
	}
	for _, scope := range roleScopes[role] {
		scopes[scope] = struct{}{}
	}
	email := strings.TrimSpace(claims.Email)
	if email == "" {
		email = v.resolveEmailBySub(ctx, strings.TrimSpace(claims.Subject))
	}
	groupList := make([]string, 0, len(groups))
	for group := range groups {
		groupList = append(groupList, group)
	}
	return CognitoClaims{
		Subject: strings.TrimSpace(claims.Subject),
		Email:   email,
		Role:    role,
		Groups:  groupList,
		Scopes:  scopes,
	}, nil
}

func (v *CognitoJwtValidator) validAudience(claims cognitoAccessClaims) bool {
	for _, aud := range claims.Audience {
		if _, ok := v.audiences[aud]; ok {
			return true
		}
	}
	_, ok := v.audiences[strings.TrimSpace(claims.ClientID)]
	return ok
}

func (v *CognitoJwtValidator) resolveEmailBySub(ctx context.Context, subject string) string {
	if subject == "" {
		return ""
	}
	if cached := v.cache.Get(subject); cached != "" {
		return cached
	}
	if v.cache.IsNegative(subject) {
		return ""
	}
	if v.lookup == nil || v.poolID == "" {
		return ""
	}
	email, notFound, err := v.lookup.LookupEmail(ctx, subject)
	if err != nil {
		// anti-regresion: BUG-0662 ver handoffs/regressions.md (no revertir sin leer)
		return ""
	}
	if notFound {
		v.cache.SetNegative(subject)
		return ""
	}
	email = strings.TrimSpace(email)
	if email != "" {
		v.cache.Set(subject, email)
	}
	return email
}

func normalizeGroups(raw []string) map[string]struct{} {
	groups := map[string]struct{}{}
	for _, group := range raw {
		if trimmed := strings.ToLower(strings.TrimSpace(group)); trimmed != "" {
			groups[trimmed] = struct{}{}
		}
	}
	return groups
}
