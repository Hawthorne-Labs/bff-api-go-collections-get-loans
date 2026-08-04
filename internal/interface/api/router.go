package handler

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers all API routes on the Gin engine.
func RegisterRoutes(
	r *gin.Engine,
	loans *LoansHandler,
	clients *ClientsHandler,
	strategy *StrategyHandler,
	users *UsersHandler,
	auth *AuthHandler,
	health *HealthHandler,
) {
	// Health
	r.GET("/health", health.Check)

	// Auth routes
	r.GET("/api/v1/auth/login", auth.Login)
	r.GET("/api/v1/auth/callback", auth.Callback)
	r.POST("/api/v1/auth/logout", auth.Logout)
	r.GET("/api/v1/auth/me", auth.Me)
	r.POST("/api/v1/auth/dev-login", auth.DevLogin)

	// Auth internal routes
	r.POST("/api/v1/auth/last-login", users.RecordLastLogin)

	// Admin routes (users)
	r.GET("/api/v1/admin/users", users.ListUsers)
	r.POST("/api/v1/admin/users", users.CreateUser)
	r.PUT("/api/v1/admin/users/:email", users.UpdateUser)
	r.POST("/api/v1/admin/users/:email/reset-password", users.ResetPassword)
	r.GET("/api/v1/admin/tenants", users.ListTenantSyncStatus)

	// User info
	r.GET("/api/v1/collections/me/permissions", users.GetMyPermissions)
	r.GET("/api/v1/collections/me/tenants", users.ListMyTenants)

	// Clients routes
	r.GET("/api/v1/collections/clients", clients.ListClients)
	r.GET("/api/v1/collections/clients/at-risk", clients.ListAtRisk)
	r.GET("/api/v1/collections/clients/contacts", clients.ListClientContacts)

	// Loans routes (core business)
	r.GET("/api/v1/collections/loans", loans.ListLoans)
	r.GET("/api/v1/collections/loans/:loanId", loans.GetLoan)
	r.GET("/api/v1/collections/loans/:loanId/balance", loans.GetLoanBalance)
	r.GET("/api/v1/collections/loans/:loanId/installments", loans.GetLoanInstallments)
	r.GET("/api/v1/collections/loans/:loanId/statement", loans.GetLoanStatement)

	// Strategy routes
	r.GET("/api/v1/collections/strategy/segmentation", strategy.GetSegmentation)
	r.GET("/api/v1/collections/strategy/assignments", strategy.ListAssignments)
	r.POST("/api/v1/collections/strategy/assignments", strategy.CreateAssignment)
	r.POST("/api/v1/collections/strategy/clean", strategy.CleanQueue)
}
