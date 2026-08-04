package middleware

import (
	"github.com/gin-gonic/gin"
)

// CognitoContext holds the identity extracted from Cognito JWT.
type CognitoContext struct {
	Sub    string
	Role   string
	Scope  string
	Email  string
	Groups []string
}

// CognitoContextMiddleware extracts Cognito context from API Gateway injected headers.
// API Gateway validates the JWT and injects X-Auth-Sub, X-Auth-Role, X-Auth-Scope.
func CognitoContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sub := c.GetHeader("X-Auth-Sub")
		role := c.GetHeader("X-Auth-Role")
		scope := c.GetHeader("X-Auth-Scope")
		email := c.GetHeader("X-Auth-Email")
		groupsStr := c.GetHeader("X-Auth-Groups")

		ctx := &CognitoContext{
			Sub:   sub,
			Role:  role,
			Scope: scope,
			Email: email,
		}
		if groupsStr != "" {
			ctx.Groups = []string{groupsStr}
		}

		c.Set("cognito_context", ctx)
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
