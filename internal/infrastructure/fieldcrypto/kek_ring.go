package fieldcrypto

import (
	"fmt"
	"os"
	"strings"
)

const (
	kekBytes      = 32
	allZeroKEKB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var forbiddenKEKKids = map[string]struct{}{
	"": {}, "pending": {}, "bootstrap": {}, "bootstrap-v1": {}, "bootstrap-v0": {},
}

// KekRing holds active and optional previous KEKs.
type KekRing struct {
	keys   map[string][]byte
	active string
}

// NewKekRing creates a KEK ring.
func NewKekRing(keys map[string][]byte, activeKID string) (*KekRing, error) {
	if activeKID == "" || keys[activeKID] == nil {
		return nil, fmt.Errorf("CRYPTO_SESSION_KEK active kid missing from ring")
	}
	for kid, key := range keys {
		if len(key) != kekBytes {
			return nil, fmt.Errorf("CRYPTO_SESSION_KEK kid length invalid: %s", kid)
		}
		_ = kid
	}
	copied := make(map[string][]byte, len(keys))
	for k, v := range keys {
		copied[k] = v
	}
	return &KekRing{keys: copied, active: activeKID}, nil
}

// ActiveKID returns the active KEK kid.
func (r *KekRing) ActiveKID() string { return r.active }

// KeyFor returns KEK bytes or SessionInvalid.
func (r *KekRing) KeyFor(kid string) ([]byte, error) {
	key, ok := r.keys[kid]
	if !ok {
		return nil, NewSessionInvalid()
	}
	return key, nil
}

// KekRingFromEnv loads CRYPTO_SESSION_KEK_* env vars.
func KekRingFromEnv() (*KekRing, error) {
	activeKID := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_KEK_ACTIVE_KID"))
	activeB64 := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_KEK_ACTIVE_B64"))
	if activeKID == "" || activeB64 == "" {
		return nil, fmt.Errorf("CRYPTO_SESSION_KEK_ACTIVE_KID and CRYPTO_SESSION_KEK_ACTIVE_B64 are required when CRYPTO_SESSION_MODE=stateless")
	}
	activeKey, err := canonicalB64URLDecode(activeB64)
	if err != nil {
		return nil, fmt.Errorf("CRYPTO_SESSION_KEK materials must be canonical base64url")
	}
	if err := assertSessionMaterialNotWeak(activeKID, activeKey, activeB64); err != nil {
		return nil, err
	}
	keys := map[string][]byte{activeKID: activeKey}
	prevKID := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_KEK_PREVIOUS_KID"))
	prevB64 := strings.TrimSpace(os.Getenv("CRYPTO_SESSION_KEK_PREVIOUS_B64"))
	if prevKID != "" || prevB64 != "" {
		if prevKID == "" || prevB64 == "" {
			return nil, fmt.Errorf("CRYPTO_SESSION_KEK_PREVIOUS_KID and CRYPTO_SESSION_KEK_PREVIOUS_B64 must both be set when using previous KEK grace")
		}
		prevKey, err := canonicalB64URLDecode(prevB64)
		if err != nil {
			return nil, fmt.Errorf("CRYPTO_SESSION_KEK materials must be canonical base64url")
		}
		if err := assertSessionMaterialNotWeak(prevKID, prevKey, prevB64); err != nil {
			return nil, err
		}
		keys[prevKID] = prevKey
	}
	return NewKekRing(keys, activeKID)
}

func assertSessionMaterialNotWeak(kid string, key []byte, keyB64 string) error {
	normalized := strings.ToLower(strings.TrimSpace(kid))
	if _, bad := forbiddenKEKKids[normalized]; bad || strings.HasPrefix(normalized, "bootstrap") {
		return fmt.Errorf("CRYPTO_SESSION_KEK kid is missing or non-usable bootstrap marker")
	}
	if len(key) != kekBytes {
		return fmt.Errorf("CRYPTO_SESSION_KEK materials must decode to 32 bytes")
	}
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero || strings.TrimSpace(keyB64) == allZeroKEKB64 {
		return fmt.Errorf("CRYPTO_SESSION_KEK must not be all-zero")
	}
	lowered := strings.ToLower(strings.TrimSpace(keyB64))
	for _, marker := range forbiddenSecretMarkers {
		if strings.Contains(lowered, marker) {
			return fmt.Errorf("CRYPTO_SESSION_KEK material looks like a non-usable placeholder")
		}
	}
	return nil
}
