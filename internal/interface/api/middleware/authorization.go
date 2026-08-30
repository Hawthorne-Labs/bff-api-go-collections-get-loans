package middleware

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

var (
	// Kept for documentation / supervisor-adjacent helpers; collections gates no longer use this list.
	allRoles        = []string{"agent", "call_center", "supervisor", "manager", "admin", "auditor"}
	supervisorRoles = []string{"supervisor", "manager", "admin"}
	// anti-regresion: BUG-0971 — agent/call_center need workload for Cobranza progress bar.
	workloadRoles = []string{"agent", "call_center", "supervisor", "manager", "admin"}
)

// EnforceRole checks the Cognito role against an allowlist.
func EnforceRole(c *gin.Context, allowed ...string) (*CognitoContext, bool) {
	ctx := GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return nil, false
	}
	if slices.Contains(allowed, ctx.Role) {
		return ctx, true
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para esta operación."}})
	return nil, false
}

// EnforceAuthenticatedRole allows any authenticated principal with a non-empty role
// (dynamic roles such as coach). Scope checks remain separate via RequireScope.
func EnforceAuthenticatedRole(c *gin.Context) (*CognitoContext, bool) {
	ctx := GetCognitoContext(c)
	if ctx == nil || ctx.Sub == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": map[string]any{"code": domain.InvalidAuthToken, "message": "El token de acceso no es válido."}})
		return nil, false
	}
	if strings.TrimSpace(ctx.Role) == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": map[string]any{"code": domain.AccessDenied, "message": "No tiene permisos para esta operación."}})
		return nil, false
	}
	return ctx, true
}

// EnforceAllRoles allows any authenticated non-empty role (ADR-2026-08-30 dynamic roles).
func EnforceAllRoles(c *gin.Context) (*CognitoContext, bool) {
	return EnforceAuthenticatedRole(c)
}

// EnforceSupervisorRoles allows supervisor/manager/admin (Python _SUPERVISOR_ADMIN).
func EnforceSupervisorRoles(c *gin.Context) (*CognitoContext, bool) {
	return EnforceRole(c, supervisorRoles...)
}

// EnforceWorkloadRoles allows agent/call_center plus mando roles.
func EnforceWorkloadRoles(c *gin.Context) (*CognitoContext, bool) {
	return EnforceRole(c, workloadRoles...)
}

// ResolveAgentID forces agent/call_center to their own sub (BUG-0945).
func ResolveAgentID(ctx *CognitoContext, requested string) string {
	if ctx == nil {
		return strings.TrimSpace(requested)
	}
	// anti-regresion: BUG-0945 ver handoffs/regressions/BUG-0945-bff-resolve-agent-id-call-center.md (no revertir sin leer)
	if ctx.Role == "agent" || ctx.Role == "call_center" {
		return ctx.Sub
	}
	if trimmed := strings.TrimSpace(requested); trimmed != "" {
		return trimmed
	}
	return ctx.Sub
}

// AllCollectionRoles returns the historical seed allowlist (tests / docs).
// Runtime collections gates use RequireAuthenticatedRole instead.
func AllCollectionRoles() []string {
	out := make([]string, len(allRoles))
	copy(out, allRoles)
	return out
}

// SupervisorAdminRoles returns mando roles.
func SupervisorAdminRoles() []string {
	out := make([]string, len(supervisorRoles))
	copy(out, supervisorRoles)
	return out
}
