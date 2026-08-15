package api

import (
	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/handler"
)

// RegisterRoutes registers all API routes on the Gin engine.
func RegisterRoutes(
	r *gin.Engine,
	loans *handler.LoansHandler,
	clients *handler.ClientsHandler,
	strategy *handler.StrategyHandler,
	users *handler.UsersHandler,
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

	// Auth internal routes
	r.POST("/api/v1/auth/last-login", users.RecordLastLogin)
	r.GET("/api/v1/auth/permissions", users.GetMyPermissions)

	// Admin routes (users)
	r.GET("/api/v1/admin/users", users.ListUsers)
	r.POST("/api/v1/admin/users", users.CreateUser)
	r.PUT("/api/v1/admin/users/:email", users.UpdateUser)
	r.PATCH("/api/v1/admin/users/:email", users.UpdateUser)
	r.POST("/api/v1/admin/users/:email/reset-password", users.ResetPassword)
	r.GET("/api/v1/admin/tenants", users.ListTenantSyncStatus)

	// Crypto session handshake (proxied to crypto-bff)
	r.POST("/api/v1/collections/crypto-session", cryptoSession.Handshake)

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

	// M2M (machine-to-machine)
	r.GET("/api/m2m/whoami", handler.M2MWhoami)

	// Audit routes
	r.GET("/api/v1/audit/recent", audit.Recent)
	r.GET("/api/v1/audit/events", audit.ByEntity)
	r.GET("/api/v1/audit/integrity", audit.Integrity)

	// Contacts (FLE-encrypted submission)
	r.POST("/api/v1/contacts", contacts.SubmitContact)
}
