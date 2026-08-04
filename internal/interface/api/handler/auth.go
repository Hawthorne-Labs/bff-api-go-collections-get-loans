package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication endpoints (Keycloak OIDC flow).
type AuthHandler struct {
	// In production, these would be injected:
	// keycloakURL   string
	// clientID      string
	// clientSecret  string
	// redirectURI   string
	// cookieDomain  string
	// sessionStore  SessionStore
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}

// Login initiates the Keycloak Authorization Code + PKCE flow.
// GET /api/v1/auth/login?return_to=/dashboard
func (h *AuthHandler) Login(c *gin.Context) {
	returnTo := c.DefaultQuery("return_to", "/")
	// In production: build Keycloak authorize URL with PKCE
	// For now, return a redirect placeholder
	c.Redirect(http.StatusFound, returnTo)
}

// Callback receives the OAuth code from Keycloak and exchanges it for tokens.
// GET /api/v1/auth/callback?code=xxx&state=xxx
func (h *AuthHandler) Callback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	_ = code
	_ = state
	// In production: validate state, exchange code for tokens, set session cookie
	c.Redirect(http.StatusFound, "/")
}

// Logout destroys the session and calls Keycloak logout.
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// In production: delete session cookie, revoke refresh token at Keycloak
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"revoked": true}})
}

// Me returns the current authenticated user's session info.
// GET /api/v1/auth/me
func (h *AuthHandler) Me(c *gin.Context) {
	// In production: check session cookie, return user info
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"authenticated": false,
		},
	})
}

// DevLogin provides a password-grant login for E2E testing in non-prod.
// POST /api/v1/auth/dev-login
func (h *AuthHandler) DevLogin(c *gin.Context) {
	// In production: gated by ENV, disabled in production
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"authenticated": false,
		},
	})
}
