package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

// MandoCollectionsScope gates supervisor+ workloads (strategy, at-risk, tenant sync).
// ADR-2026-08-30: prefer this scope over hard-coded role codes for dynamic roles.
const MandoCollectionsScope = "collections:assign"

// RequireMandoCollectionsScope enforces supervisor+ access via JWT scope claim.
func RequireMandoCollectionsScope() gin.HandlerFunc {
	return RequireScope(MandoCollectionsScope)
}

// RequireMandoCollectionsAccess enforces mando via collections:assign or legacy role fallback.
// anti-regresion: BUG-1023 ver handoffs/regressions.md (no revertir sin leer)
func RequireMandoCollectionsAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := EnforceSupervisorRoles(c); !ok {
			return
		}
		c.Next()
	}
}

// ContextHasScope reports whether the Cognito context includes a scope claim.
func ContextHasScope(ctx *CognitoContext, required string) bool {
	if ctx == nil {
		return false
	}
	return hasScope(splitScope(ctx.Scope), required)
}

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
