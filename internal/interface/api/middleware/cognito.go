package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/auth"
)

// CognitoContext holds the identity extracted from a verified Cognito access token.
type CognitoContext struct {
	Sub    string
	Role   string
	Scope  string
	Email  string
	Groups []string
}

func isPublicPath(path string) bool {
	switch {
	case path == "/health", path == "/health/live", path == "/health/ready":
		return true
	case path == "/api/v1/auth/login",
		path == "/api/v1/auth/callback",
		path == "/api/v1/auth/logout",
		path == "/api/v1/auth/me",
		path == "/api/v1/auth/dev-login":
		return true
	case strings.HasPrefix(path, "/api/m2m/"):
		return true
	default:
		return false
	}
}

// CognitoContextMiddleware validates the Authorization Bearer token (Python BFF parity).
// Does not trust browser X-Auth-* headers. /api/v1/auth/permissions and last-login stay protected.
func CognitoContextMiddleware(validator *auth.CognitoJwtValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isPublicPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		header := strings.TrimSpace(c.GetHeader("Authorization"))
		scheme, token, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": map[string]any{"code": domain.MissingAuthToken, "message": "Falta el token de acceso."}})
			return
		}
		claims, err := validator.Validate(c.Request.Context(), strings.TrimSpace(token))
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
			return
		}
		scopes := make([]string, 0, len(claims.Scopes))
		for scope := range claims.Scopes {
			scopes = append(scopes, scope)
		}
		c.Set("cognito_context", &CognitoContext{
			Sub:    claims.Subject,
			Role:   claims.Role,
			Scope:  strings.Join(scopes, " "),
			Email:  claims.Email,
			Groups: claims.Groups,
		})
		c.Next()
	}
}

// GetCognitoContext retrieves the CognitoContext from gin context.
func GetCognitoContext(c *gin.Context) *CognitoContext {
	val, exists := c.Get("cognito_context")
	if !exists {
		return nil
	}
	ctx, ok := val.(*CognitoContext)
	if !ok {
		return nil
	}
	return ctx
}
