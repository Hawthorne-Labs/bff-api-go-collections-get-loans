package middleware

import (
	"github.com/gin-gonic/gin"
)

// RequireScopeMiddleware enforces that the Cognito token includes a required scope.
func RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := GetCognitoContext(c)
		if ctx == nil {
			c.JSON(401, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
			c.Abort()
			return
		}

		scopes := splitScope(ctx.Scope)
		if !hasScope(scopes, requiredScope) {
			c.JSON(403, gin.H{"error": map[string]any{"code": 4062, "message": "scope '" + requiredScope + "' required"}})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireRoleMiddleware enforces that the Cognito token includes a role in the allowed set.
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool)
	for _, r := range allowedRoles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		ctx := GetCognitoContext(c)
		if ctx == nil {
			c.JSON(401, gin.H{"error": map[string]any{"code": 4061, "message": "El token de acceso no es válido."}})
			c.Abort()
			return
		}
		if !allowed[ctx.Role] {
			c.JSON(403, gin.H{"error": map[string]any{"code": 4062, "message": "role '" + ctx.Role + "' not permitted for this endpoint"}})
			c.Abort()
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
	result := []string{s}
	return result
}
