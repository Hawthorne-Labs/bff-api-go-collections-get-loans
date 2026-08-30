package fieldcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const defaultSessionTTL = 900

// HandshakeResult is the JSON response returned to the frontend.
type HandshakeResult struct {
	ServerPublicKey   string `json:"serverPublicKey"`
	Salt              string `json:"salt"`
	CryptoSessionID   string `json:"cryptoSessionId"`
	CryptoAccessToken string `json:"cryptoAccessToken"`
	ExpiresIn         int    `json:"expiresIn"`
}

// SessionKeyStore persists session keys behind an interface.
type SessionKeyStore interface {
	Put(sessionID string, key []byte) error
	Get(sessionID string) ([]byte, error)
	Delete(sessionID string) error
	Revoke(sessionID string) error
}

// MemorySessionStore is an in-memory session-id -> key map with TTL.
type MemorySessionStore struct {
	ttl  time.Duration
	mu   sync.RWMutex
	keys map[string]sessionEntry
}

type sessionEntry struct {
	key    []byte
	expiry time.Time
}

// NewMemorySessionStore creates a memory store.
func NewMemorySessionStore(ttlSeconds int) *MemorySessionStore {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultSessionTTL
	}
	return &MemorySessionStore{
		ttl:  time.Duration(ttlSeconds) * time.Second,
		keys: make(map[string]sessionEntry),
	}
}

func (s *MemorySessionStore) Put(sessionID string, key []byte) error {
	if len(key) != sessionKeyBytes {
		return fmt.Errorf("session key must be exactly 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[sessionID] = sessionEntry{key: key, expiry: time.Now().Add(s.ttl)}
	return nil
}

func (s *MemorySessionStore) Get(sessionID string) ([]byte, error) {
	s.mu.RLock()
	entry, ok := s.keys[sessionID]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	if time.Now().After(entry.expiry) {
		s.mu.Lock()
		delete(s.keys, sessionID)
		s.mu.Unlock()
		return nil, nil
	}
	return entry.key, nil
}

func (s *MemorySessionStore) Delete(sessionID string) error {
	s.mu.Lock()
	delete(s.keys, sessionID)
	s.mu.Unlock()
	return nil
}

func (s *MemorySessionStore) Revoke(sessionID string) error {
	return s.Delete(sessionID)
}

// CryptoSessionManager manages store-backed crypto sessions (redis/memory).
type CryptoSessionManager struct {
	store      SessionKeyStore
	secret     []byte
	issuer     string
	ttlSeconds int
}

// NewCryptoSessionManager creates a store-backed manager.
func NewCryptoSessionManager(store SessionKeyStore, signingSecret, issuer string, ttlSeconds int) *CryptoSessionManager {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultSessionTTL
	}
	return &CryptoSessionManager{
		store:      store,
		secret:     []byte(signingSecret),
		issuer:     issuer,
		ttlSeconds: ttlSeconds,
	}
}

// Mode returns "redis" for store-backed sessions.
func (m *CryptoSessionManager) Mode() string { return "redis" }

// Handshake performs ECDHE(P-256) + HKDF and stores the session key.
func (m *CryptoSessionManager) Handshake(clientPublicB64, subject, scope string) (*HandshakeResult, error) {
	clientPubBytes, err := base64.RawURLEncoding.DecodeString(clientPublicB64)
	if err != nil {
		return nil, fmt.Errorf("decode client public key: %w", err)
	}
	clientPub, err := ecdh.P256().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse client public key: %w", err)
	}
	serverPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH derive: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	sessionKey, err := deriveSessionKey(shared, salt)
	if err != nil {
		return nil, err
	}
	sessionID := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := m.store.Put(sessionID, sessionKey); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":               m.issuer,
		"aud":               jwtAudience,
		"sub":               subject,
		"scope":             scope,
		"crypto_session_id": sessionID,
		"iat":               now,
		"exp":               now + int64(m.ttlSeconds),
	}).SignedString(m.secret)
	if err != nil {
		return nil, err
	}
	return &HandshakeResult{
		ServerPublicKey:   base64.RawURLEncoding.EncodeToString(serverPriv.PublicKey().Bytes()),
		Salt:              base64.RawURLEncoding.EncodeToString(salt),
		CryptoSessionID:   sessionID,
		CryptoAccessToken: token,
		ExpiresIn:         m.ttlSeconds,
	}, nil
}

// VerifyAccessToken validates crypto access token against session id.
func (m *CryptoSessionManager) VerifyAccessToken(token, sessionID string) bool {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return m.secret, nil
	}, jwt.WithAudience(jwtAudience))
	if err != nil {
		return false
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return false
	}
	return fmt.Sprint(claims["crypto_session_id"]) == sessionID
}

// SessionKey loads the session key from the store.
func (m *CryptoSessionManager) SessionKey(sessionID string) ([]byte, error) {
	key, err := m.store.Get(sessionID)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// ResolveSessionTokenSecretFromEnv resolves CRYPTO_SESSION_TOKEN_SECRET.
func ResolveSessionTokenSecretFromEnv() (string, error) {
	dedicated := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_TOKEN_SECRET"))
	if dedicated != "" {
		if SessionModeFromEnv() == "stateless" {
			return AssertSigningOrDigestSecretNotWeak("CRYPTO_SESSION_TOKEN_SECRET", dedicated)
		}
		return dedicated, nil
	}
	if SessionModeFromEnv() == "stateless" {
		return "", fmt.Errorf("CRYPTO_SESSION_TOKEN_SECRET must be set when CRYPTO_SESSION_MODE=stateless")
	}
	if isLocalOrTestEnvironment() {
		legacy := strings.TrimSpace(os.Getenv("INTERNAL_JWT_SECRET"))
		if legacy != "" {
			return legacy, nil
		}
		return "dev-internal-jwt-secret-32-bytes-min", nil
	}
	return "", fmt.Errorf("CRYPTO_SESSION_TOKEN_SECRET must be set explicitly outside local/test environments")
}

func isLocalOrTestEnvironment() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	switch env {
	case "local", "test", "testing", "development":
		return true
	default:
		return false
	}
}

// Legacy aliases for existing wiring.
func NewSessionStore(ttlSeconds int) *MemorySessionStore {
	return NewMemorySessionStore(ttlSeconds)
}

type SessionManager = CryptoSessionManager

func NewSessionManager(store *MemorySessionStore, signingSecret, issuer string, ttlSeconds int) *CryptoSessionManager {
	return NewCryptoSessionManager(store, signingSecret, issuer, ttlSeconds)
}
