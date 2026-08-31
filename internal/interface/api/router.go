package api

import (
	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/handler"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

var adminOnly = []string{"admin"}

// RegisterRoutes registers all API routes on the Gin engine.
func RegisterRoutes(
	r *gin.Engine,
	loans *handler.LoansHandler,
	clients *handler.ClientsHandler,
	strategy *handler.StrategyHandler,
	users *handler.UsersHandler,
	roles *handler.RolesHandler,
	auth *handler.AuthHandler,
	health *handler.HealthHandler,
	cryptoSession *handler.CryptoSessionHandler,
	audit *handler.AuditHandler,
	contacts *handler.ContactsHandler,
) {
	// Health
	r.GET("/health", health.Check)
	r.GET("/health/live", health.Liveness)
	r.GET("/health/ready", health.Readiness)

	// Auth routes
	r.GET("/api/v1/auth/login", auth.Login)
	r.GET("/api/v1/auth/callback", auth.Callback)
	r.POST("/api/v1/auth/logout", auth.Logout)
	r.GET("/api/v1/auth/me", auth.Me)
	r.POST("/api/v1/auth/dev-login", auth.DevLogin)

	readScope := middleware.RequireScope("collections:read")
	anyRole := middleware.RequireAuthenticatedRole()
	mandoScope := middleware.RequireMandoCollectionsScope()
	adminRole := middleware.RequireRole(adminOnly...)

	// Auth internal routes
	authInternal := r.Group("/api/v1/auth")
	authInternal.Use(readScope, anyRole)
	{
		authInternal.POST("/last-login", users.RecordLastLogin)
		authInternal.GET("/permissions", users.GetMyPermissions)
	}

	// Admin routes (users + roles) — admin only
	admin := r.Group("/api/v1/admin")
	admin.Use(readScope, adminRole)
	{
		admin.GET("/users", users.ListUsers)
		admin.POST("/users", users.CreateUser)
		admin.PUT("/users/:userId", users.UpdateUser)
		admin.PATCH("/users/:userId", users.UpdateUser)
		admin.POST("/users/:userId/reset-password", users.ResetPassword)

		if roles != nil {
			admin.GET("/roles", roles.ListRoles)
			admin.GET("/roles/:code", roles.GetRole)
			admin.POST("/roles", roles.CreateRole)
			admin.PATCH("/roles/:code", roles.UpdateRole)
			admin.PUT("/roles/:code/permissions", roles.ReplacePermissions)
			admin.GET("/permissions", roles.ListPermissions)
		}
	}

	// Tenant sync status — mando scope (ADR-2026-08-30 dynamic roles)
	adminMando := r.Group("/api/v1/admin")
	adminMando.Use(readScope, mandoScope)
	{
		adminMando.GET("/tenants", users.ListTenantSyncStatus)
	}

	// Crypto session handshake (local ECDH / FLE)
	r.POST("/api/v1/collections/crypto-session", readScope, anyRole, cryptoSession.Handshake)

	collections := r.Group("/api/v1/collections")
	collections.Use(readScope, anyRole)
	{
		// User info
		collections.GET("/me/permissions", users.GetMyPermissions)
		collections.GET("/me/tenants", users.ListMyTenants)

		// Clients routes
		collections.GET("/clients", clients.ListClients)
		collections.GET("/clients/contacts", clients.ListClientContacts)

		// Loans routes (core business)
		collections.GET("/loans", loans.ListLoans)
		collections.GET("/loans/:loanId", loans.GetLoan)
		collections.GET("/loans/:loanId/balance", loans.GetLoanBalance)
		collections.GET("/loans/:loanId/installments", loans.GetLoanInstallments)
		collections.GET("/loans/:loanId/statement", loans.GetLoanStatement)
	}

	// At-risk clients — mando scope
	mandoCollections := r.Group("/api/v1/collections")
	mandoCollections.Use(readScope, mandoScope)
	{
		mandoCollections.GET("/clients/at-risk", clients.ListAtRisk)
	}

	// Strategy routes — mando scope
	strategyGroup := r.Group("/api/v1/collections/strategy")
	strategyGroup.Use(readScope, mandoScope)
	{
		strategyGroup.GET("/segmentation", strategy.GetSegmentation)
		strategyGroup.GET("/assignments", strategy.ListAssignments)
		strategyGroup.POST("/assignments", strategy.CreateAssignment)
		strategyGroup.POST("/clean", strategy.CleanQueue)
	}

	// M2M (machine-to-machine)
	r.GET("/api/m2m/whoami", handler.M2MWhoami)

	// Audit routes
	r.GET("/api/v1/audit/recent", audit.Recent)
	r.GET("/api/v1/audit/events", audit.ByEntity)
	r.GET("/api/v1/audit/integrity", audit.Integrity)

	// Contacts (FLE-encrypted submission)
	r.POST("/api/v1/contacts", contacts.SubmitContact)
}
