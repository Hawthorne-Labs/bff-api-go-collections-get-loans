package config

import (
	"os"
)

// Config holds all environment-based configuration for the BFF.
type Config struct {
	Port                  string
	CoreBaseURL           string
	CryptoBFFBaseURL      string
	CryptoEnabled         bool
	RequestTimeoutSeconds int
	MaxRequestBodyBytes   int
	RateLimitRequests     int
	RateLimitWindowSec    int
	AWSRegion             string
	CognitoPoolID         string
	CognitoIssuer         string
	CognitoAudience       string
	CognitoJWKSURL        string
	TrustedProxies        string
	RateLimitSkipPaths    string
	CORSSOrigins          string
	SessionBackend        string
	WarmupStrategyMarcas  string
	WarmupUserEmail       string
	LogLevel              string
	OTELServiceName       string
	CryptoSessionSecret   string
	CryptoSessionIssuer   string
	CryptoSessionTTL      int
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:                  getEnvOrDefault("PORT", "8080"),
		CoreBaseURL:           getEnvOrDefault("CORE_BASE_URL", getEnvOrDefault("API_BASE_URL", "http://localhost:9090")),
		CryptoBFFBaseURL:      getEnvOrDefault("CRYPTO_BFF_BASE_URL", "http://localhost:8081"),
		CryptoEnabled:         isTrueEnv("CRYPTO_ENABLED"),
		RequestTimeoutSeconds: getEnvIntOrDefault("REQUEST_TIMEOUT_SECONDS", 30),
		MaxRequestBodyBytes:   getEnvIntOrDefault("MAX_REQUEST_BODY_BYTES", 65536),
		RateLimitRequests:     getEnvIntOrDefault("RATE_LIMIT_REQUESTS", 60),
		RateLimitWindowSec:    getEnvIntOrDefault("RATE_LIMIT_WINDOW_SECONDS", 60),
		AWSRegion:             getEnvOrDefault("AWS_REGION", "us-east-1"),
		CognitoPoolID:         getEnvOrDefault("COGNITO_POOL_ID", ""),
		CognitoIssuer:         getEnvOrDefault("COGNITO_ISSUER", ""),
		CognitoAudience:       getEnvOrDefault("COGNITO_AUDIENCE", getEnvOrDefault("COGNITO_CLIENT_ID", "")),
		CognitoJWKSURL:        getEnvOrDefault("COGNITO_JWKS_URL", ""),
		TrustedProxies:        getEnvOrDefault("TRUSTED_PROXIES", "127.0.0.1"),
		RateLimitSkipPaths:    getEnvOrDefault("RATE_LIMIT_SKIP_PATHS", "/health"),
		CORSSOrigins:          getEnvOrDefault("BFF_CORS_ORIGINS", "http://localhost:5173"),
		SessionBackend:        getEnvOrDefault("SESSION_BACKEND", "redis"),
		WarmupStrategyMarcas:  getEnvOrDefault("WARMUP_STRATEGY_MARCAS", "PRESTAYA,PRESTAAUTO"),
		WarmupUserEmail:       getEnvOrDefault("WARMUP_USER_EMAIL", ""),
		LogLevel:              getEnvOrDefault("LOG_LEVEL", "info"),
		OTELServiceName:       getEnvOrDefault("OTEL_SERVICE_NAME", "bff-api-go-collections-get-loans"),
		CryptoSessionSecret:   getEnvOrDefault("CRYPTO_SESSION_TOKEN_SECRET", getEnvOrDefault("INTERNAL_JWT_SECRET", "dev-internal-jwt-secret-32-bytes-min")),
		CryptoSessionIssuer:   getEnvOrDefault("CRYPTO_SESSION_ISSUER", "hawthorne-bff"),
		CryptoSessionTTL:      getEnvIntOrDefault("CRYPTO_SESSION_TTL_SECONDS", 900),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n <= 0 {
		return defaultVal
	}
	return n
}

func isTrueEnv(key string) bool {
	v := os.Getenv(key)
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
