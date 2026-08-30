package fieldcrypto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// VerifiedSession holds an unwrapped stateless session key.
type VerifiedSession struct {
	SessionID  string
	SessionKey []byte
	Claims     jwt.MapClaims
}

// StatelessCryptoSessionManager seals session keys in JWT for replica-safe sessions.
type StatelessCryptoSessionManager struct {
	kek       *KekRing
	secret    []byte
	issuer    string
	namespace string
	ttl       int
}

// NewStatelessCryptoSessionManager creates a stateless manager.
func NewStatelessCryptoSessionManager(kek *KekRing, signingSecret, issuer, namespace string, ttlSeconds int) *StatelessCryptoSessionManager {
	if ttlSeconds <= 0 {
		ttlSeconds = ttlHardMax
	}
	if ttlSeconds > ttlHardMax {
		ttlSeconds = ttlHardMax
	}
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "get-loans"
	}
	return &StatelessCryptoSessionManager{
		kek:       kek,
		secret:    []byte(signingSecret),
		issuer:    issuer,
		namespace: ns,
		ttl:       ttlSeconds,
	}
}

// Mode returns "stateless".
func (m *StatelessCryptoSessionManager) Mode() string { return "stateless" }

// Namespace returns the session namespace.
func (m *StatelessCryptoSessionManager) Namespace() string { return m.namespace }

// Handshake performs ECDHE + sealed session key in JWT.
func (m *StatelessCryptoSessionManager) Handshake(
	clientPublicB64, subject, scope, tenantDigest, accessTokenHash string,
) (*HandshakeResult, error) {
	digest, err := assertTenantDigestExplicit(tenantDigest)
	if err != nil {
		return nil, err
	}
	ath := strings.ToLower(strings.TrimSpace(accessTokenHash))
	if len(ath) != 64 || !isHex(ath) {
		return nil, NewSessionInvalid()
	}

	clientPubBytes, err := canonicalB64URLDecode(clientPublicB64)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	clientPub, err := ecdh.P256().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	serverPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, NewSessionInvalid()
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
	now := time.Now().Unix()
	expiresAt := now + int64(m.ttl)
	kekKID := m.kek.ActiveKID()
	aadBytes := sessionAAD(m.namespace, digest, sessionID, subject, scope, cryptoVersion, now, expiresAt, kekKID, ath)
	nonce := make([]byte, statelessNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	kek, err := m.kek.KeyFor(kekKID)
	if err != nil {
		return nil, err
	}
	sealed, err := sealWithAESGCM(kek, nonce, sessionKey, aadBytes)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":               m.issuer,
		"aud":               jwtAudience,
		"sub":               subject,
		"scope":             scope,
		"crypto_session_id": sessionID,
		"namespace":         m.namespace,
		"tenant_digest":     digest,
		"crypto_version":    cryptoVersion,
		"iat":               now,
		"exp":               expiresAt,
		"kek_kid":           kekKID,
		"access_token_hash": ath,
		"session_envelope": map[string]any{
			"nonce":      b64URLEncode(nonce),
			"ciphertext": b64URLEncode(sealed),
		},
	}).SignedString(m.secret)
	if err != nil {
		return nil, err
	}
	return &HandshakeResult{
		ServerPublicKey:   b64URLEncode(serverPriv.PublicKey().Bytes()),
		Salt:              b64URLEncode(salt),
		CryptoSessionID:   sessionID,
		CryptoAccessToken: token,
		ExpiresIn:         m.ttl,
	}, nil
}

// VerifyAccessToken validates token/session binding without unwrapping key.
func (m *StatelessCryptoSessionManager) VerifyAccessToken(token, sessionID string) bool {
	claims, err := m.parseToken(token)
	if err != nil {
		return false
	}
	return claims["crypto_session_id"] == sessionID
}

// SessionKey always returns nil for stateless mode.
func (m *StatelessCryptoSessionManager) SessionKey(string) ([]byte, error) {
	return nil, nil
}

// Resolve unwraps session key from crypto access token.
func (m *StatelessCryptoSessionManager) Resolve(
	cryptoAccessToken, sessionID, tenantDigest, authorization, namespace string,
) (*VerifiedSession, error) {
	return m.resolveUnchecked(cryptoAccessToken, sessionID, tenantDigest, authorization, namespace)
}

func (m *StatelessCryptoSessionManager) resolveUnchecked(
	cryptoAccessToken, sessionID, tenantDigest, authorization, namespace string,
) (*VerifiedSession, error) {
	expectedNS := strings.TrimSpace(namespace)
	if expectedNS == "" {
		expectedNS = m.namespace
	}
	digest, err := assertTenantDigestExplicit(tenantDigest)
	if err != nil {
		return nil, err
	}
	bearerHash, err := HashAccessToken(authorization)
	if err != nil {
		return nil, err
	}
	claims, err := m.parseToken(cryptoAccessToken)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	if fmt.Sprint(claims["crypto_session_id"]) != sessionID {
		return nil, NewSessionInvalid()
	}
	if fmt.Sprint(claims["namespace"]) != expectedNS {
		return nil, NewSessionInvalid()
	}
	if fmt.Sprint(claims["tenant_digest"]) != digest {
		return nil, NewSessionInvalid()
	}
	if fmt.Sprint(claims["crypto_version"]) != cryptoVersion {
		return nil, NewSessionInvalid()
	}
	claimATH := strings.ToLower(fmt.Sprint(claims["access_token_hash"]))
	if !hmac.Equal([]byte(claimATH), []byte(bearerHash)) {
		return nil, NewSessionInvalid()
	}
	issuedAt, err := claimInt64(claims, "iat")
	if err != nil {
		return nil, NewSessionInvalid()
	}
	expiresAt, err := claimInt64(claims, "exp")
	if err != nil {
		return nil, NewSessionInvalid()
	}
	now := time.Now().Unix()
	if expiresAt-issuedAt > ttlHardMax {
		return nil, NewSessionInvalid()
	}
	if expiresAt <= now-int64(clockSkewSeconds) {
		return nil, NewSessionInvalid()
	}
	kekKID := fmt.Sprint(claims["kek_kid"])
	envRaw, ok := claims["session_envelope"].(map[string]any)
	if !ok {
		return nil, NewSessionInvalid()
	}
	nonce, err := canonicalB64URLDecode(fmt.Sprint(envRaw["nonce"]))
	if err != nil {
		return nil, NewSessionInvalid()
	}
	ciphertext, err := canonicalB64URLDecode(fmt.Sprint(envRaw["ciphertext"]))
	if err != nil {
		return nil, NewSessionInvalid()
	}
	if len(nonce) != statelessNonceLen || len(ciphertext) == 0 {
		return nil, NewSessionInvalid()
	}
	aadBytes := sessionAAD(
		fmt.Sprint(claims["namespace"]),
		fmt.Sprint(claims["tenant_digest"]),
		sessionID,
		fmt.Sprint(claims["sub"]),
		fmt.Sprint(claims["scope"]),
		fmt.Sprint(claims["crypto_version"]),
		issuedAt,
		expiresAt,
		kekKID,
		claimATH,
	)
	kek, err := m.kek.KeyFor(kekKID)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	key, err := openWithAESGCM(kek, nonce, ciphertext, aadBytes)
	if err != nil {
		return nil, NewSessionInvalid()
	}
	if len(key) != sessionKeyBytes {
		return nil, NewSessionInvalid()
	}
	return &VerifiedSession{SessionID: sessionID, SessionKey: key, Claims: claims}, nil
}

func (m *StatelessCryptoSessionManager) parseToken(token string) (jwt.MapClaims, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return m.secret, nil
	}, jwt.WithAudience(jwtAudience), jwt.WithIssuer(m.issuer), jwt.WithLeeway(clockSkewSeconds*time.Second))
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, NewSessionInvalid()
	}
	return claims, nil
}

// BuildStatelessManagerFromEnv constructs a stateless manager from env.
func BuildStatelessManagerFromEnv(signingSecret, issuer string) (*StatelessCryptoSessionManager, error) {
	kek, err := KekRingFromEnv()
	if err != nil {
		return nil, err
	}
	ttl := 300
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
	namespace := getEnvDefault("CRYPTO_SESSION_NAMESPACE", "get-loans")
	return NewStatelessCryptoSessionManager(kek, signingSecret, issuer, namespace, ttl), nil
}
