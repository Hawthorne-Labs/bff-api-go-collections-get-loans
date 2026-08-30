package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

// RequireScope enforces that the Cognito token includes a required scope.
func RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := GetCognitoContext(c)
		if ctx == nil || ctx.Sub == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
			return
		}

		scopes := splitScope(ctx.Scope)
		if !hasScope(scopes, requiredScope) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para esta operación."}})
			return
		}
		c.Next()
	}
}

// RequireRole enforces that the Cognito token includes a role in the allowed set.
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedRoles))
	for _, r := range allowedRoles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		ctx := GetCognitoContext(c)
		if ctx == nil || ctx.Sub == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
			return
		}
		if !allowed[ctx.Role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para esta operación."}})
			return
		}
		c.Next()
	}
}

// RequireAuthenticatedRole allows any authenticated principal with a non-empty role claim.
// Used for collections / crypto-session / auth permissions so dynamic roles are not blocked.
func RequireAuthenticatedRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := EnforceAuthenticatedRole(c); !ok {
			return
		}
		c.Next()
	}
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	result := make([]string, 0)
	for _, s := range splitWords(scope) {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func hasScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}

func splitWords(s string) []string {
	return strings.Fields(s)
}
