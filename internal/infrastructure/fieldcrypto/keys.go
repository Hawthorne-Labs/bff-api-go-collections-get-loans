package fieldcrypto

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const keyLen = 32

// KeyProvider resolves AES-256 keys by kid.
type KeyProvider interface {
	ActiveKID() string
	KeyFor(kid string) ([]byte, error)
}

func decodeKey(material string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(material)
	if err != nil || len(raw) != keyLen {
		return nil, fmt.Errorf("crypto key must be 32 bytes (base64url-encoded)")
	}
	return raw, nil
}

// EnvKeyProvider loads keys from CRYPTO_KEYS + CRYPTO_ACTIVE_KID.
type EnvKeyProvider struct {
	keys   map[string][]byte
	active string
}

// NewEnvKeyProvider creates a provider from explicit key map.
func NewEnvKeyProvider(keys map[string][]byte, activeKID string) (*EnvKeyProvider, error) {
	if activeKID == "" || keys[activeKID] == nil {
		return nil, fmt.Errorf("active kid is not present in the key set")
	}
	copied := make(map[string][]byte, len(keys))
	for k, v := range keys {
		copied[k] = v
	}
	return &EnvKeyProvider{keys: copied, active: activeKID}, nil
}

// EnvKeyProviderFromEnv loads CRYPTO_KEYS and CRYPTO_ACTIVE_KID.
func EnvKeyProviderFromEnv() (*EnvKeyProvider, error) {
	raw := strings.TrimSpace(os.Getenv("CRYPTO_KEYS"))
	keys := make(map[string][]byte)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" || !strings.Contains(pair, ":") {
			continue
		}
		kid, material, _ := strings.Cut(pair, ":")
		kid = strings.TrimSpace(kid)
		material = strings.TrimSpace(material)
		if kid == "" || material == "" {
			continue
		}
		key, err := decodeKey(material)
		if err != nil {
			return nil, err
		}
		keys[kid] = key
	}
	active := strings.TrimSpace(os.Getenv("CRYPTO_ACTIVE_KID"))
	if len(keys) == 0 || active == "" {
		return nil, fmt.Errorf("CRYPTO_KEYS and CRYPTO_ACTIVE_KID must be configured")
	}
	return NewEnvKeyProvider(keys, active)
}

func (p *EnvKeyProvider) ActiveKID() string { return p.active }

func (p *EnvKeyProvider) KeyFor(kid string) ([]byte, error) {
	key, ok := p.keys[kid]
	if !ok {
		return nil, NewUnknownKid()
	}
	return key, nil
}

// FixedSessionKeyProvider binds enc:v1 kid to one verified session key.
type FixedSessionKeyProvider struct {
	sessionID  string
	sessionKey []byte
}

// NewFixedSessionKeyProvider creates a request-scoped provider.
func NewFixedSessionKeyProvider(sessionID string, sessionKey []byte) (*FixedSessionKeyProvider, error) {
	if len(sessionKey) != keyLen {
		return nil, NewSessionInvalid()
	}
	return &FixedSessionKeyProvider{sessionID: sessionID, sessionKey: sessionKey}, nil
}

func (p *FixedSessionKeyProvider) ActiveKID() string { return p.sessionID }

func (p *FixedSessionKeyProvider) KeyFor(kid string) ([]byte, error) {
	if kid != p.sessionID {
		return nil, NewUnknownKid()
	}
	return p.sessionKey, nil
}

// SessionKeyProvider resolves keys from a store-backed session manager.
type SessionKeyProvider struct {
	mgr *CryptoSessionManager
}

// NewSessionKeyProvider creates a session-only key provider.
func NewSessionKeyProvider(mgr *CryptoSessionManager) *SessionKeyProvider {
	return &SessionKeyProvider{mgr: mgr}
}

func (p *SessionKeyProvider) ActiveKID() string {
	return ""
}

func (p *SessionKeyProvider) KeyFor(kid string) ([]byte, error) {
	key, err := p.mgr.SessionKey(kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, NewUnknownKid()
	}
	return key, nil
}
