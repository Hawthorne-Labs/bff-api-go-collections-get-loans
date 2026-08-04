package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api"
)

func main() {
	cfg := config.Load()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes
	api.RegisterRoutes(router, cfg)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on :%s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
