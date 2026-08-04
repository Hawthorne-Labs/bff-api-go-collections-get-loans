package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/cryptobffclient"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/handler"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

func main() {
	cfg := config.Load()

	// --- Infrastructure ---
	coreClient := coreclient.NewCoreClient(cfg)
	cryptoClient := cryptobffclient.NewCryptoBFFClient(cfg)

	// --- Application (Usecases) ---
	loansUC := usecases.NewLoansUsecase(coreClient)
	clientsUC := usecases.NewClientsUsecase(coreClient)
	strategyUC := usecases.NewStrategyUsecase(coreClient)
	usersUC := usecases.NewUsersUsecase(coreClient)

	// --- Handlers ---
	loansH := handler.NewLoansHandler(loansUC)
	clientsH := handler.NewClientsHandler(clientsUC)
	strategyH := handler.NewStrategyHandler(strategyUC)
	usersH := handler.NewUsersHandler(usersUC)
	authH := handler.NewAuthHandler()
	healthH := handler.NewHealthHandler()

	// --- Router ---
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(middleware.TracingMiddleware())
	r.Use(middleware.CognitoContextMiddleware())
	r.Use(middleware.AuditMiddleware())
	r.Use(middleware.CryptoMiddleware(cfg.CryptoEnabled, cryptoClient.NewCryptoClient(cfg.CryptoBFFBaseURL)))

	// Register all API routes
	handler.RegisterRoutes(r, loansH, clientsH, strategyH, usersH, authH, healthH)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting BFF get-loans on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
