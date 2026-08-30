package fieldcrypto

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	managerMu     sync.Mutex
	globalStore   SessionKeyStore
	globalManager any
)

// SessionModeFromEnv returns CRYPTO_SESSION_MODE.
func SessionModeFromEnv() string {
	return strings.ToLower(strings.TrimSpace(os.Getenv("CRYPTO_SESSION_MODE")))
}

func redisRollbackAllowlisted() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CRYPTO_SESSION_REDIS_ROLLBACK")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// AssertSessionModeAllowed validates session mode for environment.
func AssertSessionModeAllowed(mode string) error {
	if mode == "stateless" {
		return nil
	}
	if mode == "" || mode == "store" || mode == "redis" {
		if isLocalOrTestEnvironment() {
			return nil
		}
		if mode == "redis" && redisRollbackAllowlisted() {
			return nil
		}
		return fmt.Errorf("CRYPTO_SESSION_MODE must be explicitly 'stateless' outside local/test (redis requires CRYPTO_SESSION_REDIS_ROLLBACK=true)")
	}
	return fmt.Errorf("CRYPTO_SESSION_MODE must be 'stateless' or 'redis' (rollback)")
}

// BuildSessionStoreFromEnv creates memory or redis session store.
func BuildSessionStoreFromEnv() (SessionKeyStore, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CRYPTO_SESSION_BACKEND")))
	ttl := defaultSessionTTL
	if v := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_TTL_SECONDS")); v != "" {
		n := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			ttl = n
		}
	}
	switch backend {
	case "memory":
		if !isLocalOrTestEnvironment() {
			return nil, fmt.Errorf("CRYPTO_SESSION_BACKEND=memory is only allowed when ENVIRONMENT is local, test, testing, or development")
		}
		return NewMemorySessionStore(ttl), nil
	case "redis":
		namespace := getEnvDefault("CRYPTO_SESSION_NAMESPACE", "get-loans")
		client, err := redisClientFromEnv()
		if err != nil {
			return nil, err
		}
		return NewRedisCryptoSessionStore(client, namespace, ttl), nil
	case "":
		return nil, fmt.Errorf("CRYPTO_SESSION_BACKEND must be set explicitly to 'redis' or 'memory'")
	default:
		return nil, fmt.Errorf("unsupported CRYPTO_SESSION_BACKEND: %s", backend)
	}
}

// ManagerFromEnv creates a store-backed session manager.
func ManagerFromEnv(store SessionKeyStore) (*CryptoSessionManager, error) {
	secret, err := ResolveSessionTokenSecretFromEnv()
	if err != nil {
		return nil, err
	}
	issuer := getEnvDefault("CRYPTO_SESSION_ISSUER", "hawthorne-bff")
	ttl := defaultSessionTTL
	if v := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_TTL_SECONDS")); v != "" {
		n := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			ttl = n
		}
	}
	return NewCryptoSessionManager(store, secret, issuer, ttl), nil
}

// ResetSessionManagerForTests clears cached manager.
func ResetSessionManagerForTests() {
	managerMu.Lock()
	defer managerMu.Unlock()
	globalStore = nil
	globalManager = nil
}

// GetSessionManager returns store-backed or stateless manager per env.
func GetSessionManager() (any, error) {
	managerMu.Lock()
	defer managerMu.Unlock()
	if globalManager != nil {
		return globalManager, nil
	}
	mode := SessionModeFromEnv()
	if err := AssertSessionModeAllowed(mode); err != nil {
		return nil, err
	}
	if mode == "stateless" {
		secret, err := ResolveSessionTokenSecretFromEnv()
		if err != nil {
			return nil, err
		}
		issuer := getEnvDefault("CRYPTO_SESSION_ISSUER", "hawthorne-bff")
		mgr, err := BuildStatelessManagerFromEnv(secret, issuer)
		if err != nil {
			return nil, err
		}
		globalManager = mgr
		return mgr, nil
	}
	store, err := BuildSessionStoreFromEnv()
	if err != nil {
		return nil, err
	}
	globalStore = store
	mgr, err := ManagerFromEnv(store)
	if err != nil {
		return nil, err
	}
	globalManager = mgr
	return mgr, nil
}

// SessionManagerMode returns mode string for any manager type.
func SessionManagerMode(mgr any) string {
	switch v := mgr.(type) {
	case *StatelessCryptoSessionManager:
		return v.Mode()
	case *CryptoSessionManager:
		return v.Mode()
	default:
		return "redis"
	}
}
