// Package fieldcrypto implements ECDHE(P-256) + HKDF-SHA256 crypto-session
// handshake compatible with the Python BFF's CryptoSessionManager (enc:v1).
//
// The SPA sends its P-256 public key; the BFF generates an ephemeral P-256
// keypair, derives a shared secret via ECDH, then HKDF-SHA256 with info
// "hawthorne-fieldcrypto-v1" produces a 32-byte AES session key. The key is
// stored in-memory only (never persisted/logged). A signed HS256 JWT
// (crypto_access_token) lets the API Gateway validate the session without
// being able to decrypt.
package fieldcrypto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

const (
	info       = "hawthorne-fieldcrypto-v1"
	audience   = "crypto-session"
	defaultTTL = 900 // seconds
)

// ---------- base64url helpers ----------

func b64uEnc(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func b64uDec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ---------- SessionStore ----------

// SessionStore is an in-memory session-id -> key map with TTL.
// Keys are never persisted or logged.
type SessionStore struct {
	ttl  time.Duration
	mu   sync.RWMutex
	keys map[string]sessionEntry
}

type sessionEntry struct {
	key    []byte
	expiry time.Time
}

// NewSessionStore creates a store with the given TTL.
func NewSessionStore(ttlSeconds int) *SessionStore {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTL
	}
	return &SessionStore{
		ttl:  time.Duration(ttlSeconds) * time.Second,
		keys: make(map[string]sessionEntry),
	}
}

// Put stores a session key.
func (s *SessionStore) Put(sessionID string, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[sessionID] = sessionEntry{key: key, expiry: time.Now().Add(s.ttl)}
}

// Get retrieves a session key. Returns nil if expired or missing.
func (s *SessionStore) Get(sessionID string) []byte {
	s.mu.RLock()
	entry, ok := s.keys[sessionID]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(entry.expiry) {
		s.mu.Lock()
		delete(s.keys, sessionID)
		s.mu.Unlock()
		return nil
	}
	return entry.key
}

// ---------- SessionManager ----------

// HandshakeResult is the JSON response returned to the frontend.
type HandshakeResult struct {
	ServerPublicKey   string `json:"serverPublicKey"`
	Salt              string `json:"salt"`
	CryptoSessionID   string `json:"cryptoSessionId"`
	CryptoAccessToken string `json:"cryptoAccessToken"`
	ExpiresIn         int    `json:"expiresIn"`
}

// SessionManager performs the local P-256 ECDH handshake.
type SessionManager struct {
	store         *SessionStore
	signingSecret []byte
	issuer        string
	ttlSeconds    int
}

// NewSessionManager creates a manager.
func NewSessionManager(store *SessionStore, signingSecret string, issuer string, ttlSeconds int) *SessionManager {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTL
	}
	return &SessionManager{
		store:         store,
		signingSecret: []byte(signingSecret),
		issuer:        issuer,
		ttlSeconds:    ttlSeconds,
	}
}

// Handshake performs the ECDHE(P-256) + HKDF-SHA256 handshake.
// clientPublicB64 is the base64url-encoded uncompressed P-256 point from the SPA.
func (m *SessionManager) Handshake(clientPublicB64 string, subject string, scope string) (*HandshakeResult, error) {
	// Decode client public key (uncompressed P-256 point: 0x04 + 32 + 32 = 65 bytes)
	clientPubBytes, err := b64uDec(clientPublicB64)
	if err != nil {
		return nil, fmt.Errorf("decode client public key: %w", err)
	}

	clientPub, err := ecdh.P256().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse client public key: %w", err)
	}

	// Generate ephemeral server P-256 keypair
	serverPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}

	// ECDH shared secret
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH derive: %w", err)
	}

	// HKDF-SHA256 to derive session key
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	sessionKey := hkdfSHA256(shared, salt, []byte(info), 32)

	// Store session
	sessionID := randomHex(16)
	m.store.Put(sessionID, sessionKey)

	// Server public key (uncompressed point)
	serverPubBytes := serverPriv.PublicKey().Bytes()

	// Sign JWT
	now := time.Now()
	token, err := m.signJWT(subject, scope, sessionID, now)
	if err != nil {
		return nil, fmt.Errorf("sign JWT: %w", err)
	}

	return &HandshakeResult{
		ServerPublicKey:   b64uEnc(serverPubBytes),
		Salt:              b64uEnc(salt),
		CryptoSessionID:   sessionID,
		CryptoAccessToken: token,
		ExpiresIn:         m.ttlSeconds,
	}, nil
}

// SessionKey returns the key for a session ID, or nil if not found/expired.
func (m *SessionManager) SessionKey(sessionID string) []byte {
	return m.store.Get(sessionID)
}

// ---------- HS256 JWT (manual, no external dependency) ----------

func (m *SessionManager) signJWT(subject, scope, sessionID string, now time.Time) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss":               m.issuer,
		"aud":               audience,
		"sub":               subject,
		"scope":             scope,
		"crypto_session_id": sessionID,
		"iat":               now.Unix(),
		"exp":               now.Add(time.Duration(m.ttlSeconds) * time.Second).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := b64uEnc(headerJSON)
	claimsB64 := b64uEnc(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	mac := hmac.New(sha256.New, m.signingSecret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	return signingInput + "." + b64uEnc(sig), nil
}

// ---------- HKDF-SHA256 (extract-then-expand) ----------

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	// Extract
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	// Expand (single iteration for 32 bytes with SHA-256)
	mac2 := hmac.New(sha256.New, prk)
	mac2.Write(info)
	mac2.Write([]byte{1})
	return mac2.Sum(nil)[:length]
}

// ---------- helpers ----------

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return strconv.FormatInt(time.Now().UnixNano(), 36) + fmt.Sprintf("%x", b)[:n]
}
