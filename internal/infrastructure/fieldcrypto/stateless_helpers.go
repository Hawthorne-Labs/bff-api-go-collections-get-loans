package fieldcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/hkdf"
)

const (
	hkdfInfo          = "hawthorne-fieldcrypto-v1"
	jwtAudience       = "crypto-session"
	cryptoVersion     = "v1"
	sessionKeyBytes   = 32
	statelessNonceLen = 12
	ttlHardMax        = 300
	clockSkewSeconds  = 5
)

var (
	forbiddenDigests = map[string]struct{}{
		"": {}, "default": {}, "all": {}, "*": {}, "null": {}, "none": {}, "undefined": {}, "anonymous": {},
	}
	forbiddenSecretMarkers = []string{
		"bootstrap-crypto",
		"bootstrap-v1",
		"pending_rotation",
		"replace_via_approved",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	b64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// AssertSigningOrDigestSecretNotWeak validates session/digest secrets.
func AssertSigningOrDigestSecretNotWeak(name, value string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", fmt.Errorf("%s is required when CRYPTO_SESSION_MODE=stateless", name)
	}
	if len(raw) < 32 {
		return "", fmt.Errorf("%s must be at least 32 bytes", name)
	}
	lowered := strings.ToLower(raw)
	for _, marker := range forbiddenSecretMarkers {
		if strings.Contains(lowered, marker) {
			return "", fmt.Errorf("%s looks like a non-usable bootstrap placeholder", name)
		}
	}
	return raw, nil
}

func deriveSessionKey(shared, salt []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo))
	key := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func sessionAAD(namespace, tenantDigest, sessionID, sub, scope, version string, issuedAt, expiresAt int64, kekKID, accessTokenHash string) []byte {
	return []byte(strings.Join([]string{
		namespace,
		tenantDigest,
		sessionID,
		sub,
		scope,
		version,
		fmt.Sprintf("%d", issuedAt),
		fmt.Sprintf("%d", expiresAt),
		kekKID,
		accessTokenHash,
	}, "|"))
}

func canonicalB64URLDecode(text string) ([]byte, error) {
	if text == "" {
		return nil, NewSessionInvalid()
	}
	for _, ch := range text {
		if ch <= ' ' || ch == '=' {
			return nil, NewSessionInvalid()
		}
	}
	if !b64URLPattern.MatchString(text) {
		return nil, NewSessionInvalid()
	}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	if b64URLEncode(raw) != text {
		return nil, NewSessionInvalid()
	}
	return raw, nil
}

// HashAccessToken derives SHA-256 hex of bearer token.
func HashAccessToken(authorizationOrToken string) (string, error) {
	token := strings.TrimSpace(authorizationOrToken)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return "", NewSessionInvalid()
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

func assertTenantDigestExplicit(tenantDigest string) (string, error) {
	digest := strings.TrimSpace(tenantDigest)
	if _, forbidden := forbiddenDigests[strings.ToLower(digest)]; forbidden || len(digest) < 16 {
		return "", NewSessionInvalid()
	}
	return digest, nil
}

func sealWithAESGCM(key, nonce, plain, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plain, aad), nil
}

func openWithAESGCM(key, nonce, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, sealed, aad)
}

func claimInt64(claims jwt.MapClaims, key string) (int64, error) {
	v, ok := claims[key]
	if !ok {
		return 0, fmt.Errorf("missing claim")
	}
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("invalid claim")
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
