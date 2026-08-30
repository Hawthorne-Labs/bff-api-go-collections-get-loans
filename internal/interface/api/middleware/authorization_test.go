package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestResolveAgentIDCallCenterForcedToSub(t *testing.T) {
	// anti-regresion: BUG-0945 — call_center treated like agent
	tests := []struct {
		name      string
		role      string
		sub       string
		requested string
		want      string
	}{
		{name: "agent_ignores_requested", role: "agent", sub: "sub-agent", requested: "other", want: "sub-agent"},
		{name: "call_center_ignores_requested", role: "call_center", sub: "sub-cc", requested: "other", want: "sub-cc"},
		{name: "supervisor_keeps_requested", role: "supervisor", sub: "sub-sup", requested: "agent-9", want: "agent-9"},
		{name: "manager_defaults_to_sub", role: "manager", sub: "sub-mgr", requested: "", want: "sub-mgr"},
		{name: "coach_keeps_requested", role: "coach", sub: "sub-coach", requested: "agent-1", want: "agent-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveAgentID(&CognitoContext{Sub: tt.sub, Role: tt.role}, tt.requested)
			if got != tt.want {
				t.Errorf("ResolveAgentID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequireAuthenticatedRoleAllowsCallCenter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("cognito_context", &CognitoContext{
			Sub:   "cc-1",
			Role:  "call_center",
			Scope: "collections:read",
		})
		c.Next()
	})
	r.GET("/loans", RequireAuthenticatedRole(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/loans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestRequireAuthenticatedRoleAllowsDynamicCoach(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("cognito_context", &CognitoContext{
			Sub:   "coach-1",
			Role:  "coach",
			Scope: "collections:read",
		})
		c.Next()
	})
	r.GET("/loans", RequireAuthenticatedRole(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/loans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestEnforceAuthenticatedRoleRejectsEmptyRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("cognito_context", &CognitoContext{
			Sub:   "x",
			Role:  "",
			Scope: "collections:read",
		})
		c.Next()
	})
	r.GET("/loans", RequireAuthenticatedRole(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/loans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestEnforceSupervisorRolesBlocksCallCenter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("cognito_context", &CognitoContext{
			Sub:   "cc-1",
			Role:  "call_center",
			Scope: "collections:read",
		})
		c.Next()
	})
	r.POST("/strategy", func(c *gin.Context) {
		if _, ok := EnforceSupervisorRoles(c); !ok {
			return
		}
		c.Status(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/strategy", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestRequireRoleAdminStillBlocksCoach(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("cognito_context", &CognitoContext{
			Sub:   "coach-1",
			Role:  "coach",
			Scope: "collections:read",
		})
		c.Next()
	})
	r.GET("/admin/roles", RequireRole("admin"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/roles", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}
