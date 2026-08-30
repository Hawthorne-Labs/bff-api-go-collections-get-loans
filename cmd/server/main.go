package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/application/usecases"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/auth"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/cognito"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/config"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/cryptobffclient"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/fieldcrypto"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/handler"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/interface/api/middleware"
)

func main() {
	cfg := config.Load()

	coreClient := coreclient.NewCoreClient(cfg)

	emailLookup, err := auth.NewAWSCognitoEmailLookup(context.Background(), cfg.AWSRegion, cfg.CognitoPoolID)
	if err != nil {
		log.Printf("cognito AdminGetUser client unavailable: %v", err)
	}
	cognitoValidator := auth.NewCognitoJwtValidator(cfg, emailLookup, auth.NewIdentityEmailCache(cfg.RedisURL))

	cognitoUsers, err := cognito.NewUserClient(context.Background(), cfg.AWSRegion, cfg.CognitoPoolID)
	if err != nil {
		log.Printf("cognito user admin client unavailable: %v", err)
	}
	var identityProvisioner usecases.IdentityProvisioner
	if cognitoUsers != nil {
		identityProvisioner = cognitoUsers
	}

	loansUC := usecases.NewLoansUsecase(coreClient)
	clientsUC := usecases.NewClientsUsecase(coreClient)
	strategyUC := usecases.NewStrategyUsecase(coreClient)
	usersUC := usecases.NewUsersUsecase(coreClient, identityProvisioner)

	cognitoGroups, err := cognito.NewGroupClient(context.Background(), cfg.AWSRegion, cfg.CognitoPoolID)
	if err != nil {
		log.Printf("cognito group client unavailable: %v", err)
	}
	var roleProvisioner usecases.RoleGroupProvisioner
	if cognitoGroups != nil {
		roleProvisioner = cognitoGroups
	}
	rolesUC := usecases.NewRolesUsecase(coreClient, roleProvisioner)

	loansH := handler.NewLoansHandler(loansUC)
	clientsH := handler.NewClientsHandler(clientsUC)
	strategyH := handler.NewStrategyHandler(strategyUC)
	usersH := handler.NewUsersHandler(usersUC)
	rolesH := handler.NewRolesHandler(rolesUC)
	authH := handler.NewAuthHandler()
	healthH := handler.NewHealthHandler()

	cryptoSessionMgr, err := fieldcrypto.GetSessionManager()
	if err != nil {
		log.Printf("crypto session manager unavailable: %v", err)
	}
	var tenantAuthority fieldcrypto.TenantAuthority
	if fieldcrypto.SessionModeFromEnv() == "stateless" {
		mgmtClient, mgmtErr := fieldcrypto.ManagementTenantClientFromEnv(coreclient.NewMtlsHTTPClient(5 * time.Second))
		if mgmtErr != nil {
			log.Printf("tenant authority unavailable: %v", mgmtErr)
			tenantAuthority = fieldcrypto.FailClosedTenantAuthority{}
		} else {
			tenantAuthority, err = fieldcrypto.BuildTenantAuthorityFromEnv(mgmtClient)
			if err != nil {
				log.Printf("tenant authority unavailable: %v", err)
				tenantAuthority = fieldcrypto.FailClosedTenantAuthority{}
			} else {
				fieldcrypto.SetTenantAuthority(tenantAuthority)
			}
		}
	}
	cryptoSessionH := handler.NewCryptoSessionHandler(cryptoSessionMgr, tenantAuthority)
	auditH := handler.NewAuditHandler(coreClient)
	cryptoBffClient := cryptobffclient.NewCryptoBFFClient(cfg)
	contactsH := handler.NewContactsHandler(coreClient, cryptoBffClient)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(middleware.RateLimitMiddleware(
		middleware.NewMemoryRateLimitStore(cfg.RateLimitRequests, cfg.RateLimitWindowSec),
		cfg.TrustedProxies,
		cfg.RateLimitSkipPaths,
	))
	r.Use(middleware.RequestSizeLimitMiddleware(cfg.MaxRequestBodyBytes))
	r.Use(middleware.TracingMiddleware())
	r.Use(middleware.CognitoContextMiddleware(cognitoValidator))
	r.Use(middleware.AuditMiddleware())
	if cfg.CryptoEnabled {
		cryptoSettings := fieldcrypto.CryptoSettingsFromEnv()
		var fieldCryptoService *fieldcrypto.FieldCryptoService
		switch mgr := cryptoSessionMgr.(type) {
		case *fieldcrypto.CryptoSessionManager:
			fieldCryptoService = fieldcrypto.NewFieldCryptoService(fieldcrypto.NewSessionKeyProvider(mgr))
		default:
			if provider, err := fieldcrypto.EnvKeyProviderFromEnv(); err == nil {
				fieldCryptoService = fieldcrypto.NewFieldCryptoService(provider)
			} else {
				placeholder, _ := fieldcrypto.NewEnvKeyProvider(map[string][]byte{"unused": bytesRepeat(32, 1)}, "unused")
				fieldCryptoService = fieldcrypto.NewFieldCryptoService(placeholder)
			}
		}
		r.Use(middleware.FieldCryptoMiddleware(middleware.FieldCryptoMiddlewareConfig{
			Enabled:         true,
			Service:         fieldCryptoService,
			Policy:          cryptoSettings.Policy(),
			Settings:        cryptoSettings,
			SessionManager:  cryptoSessionMgr,
			TenantAuthority: tenantAuthority,
		}))
	}
	r.Use(middleware.CORS(cfg.CORSSOrigins))

	api.RegisterRoutes(r, loansH, clientsH, strategyH, usersH, rolesH, authH, healthH, cryptoSessionH, auditH, contactsH)

	if email := strings.TrimSpace(cfg.WarmupUserEmail); email != "" {
		marcas := splitCSV(cfg.WarmupStrategyMarcas)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			strategyUC.WarmReadPaths(ctx, email, marcas)
			log.Printf("strategy warmup done marcas=%v", marcas)
		}()
	}

	port := cfg.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting BFF get-loans on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func bytesRepeat(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
