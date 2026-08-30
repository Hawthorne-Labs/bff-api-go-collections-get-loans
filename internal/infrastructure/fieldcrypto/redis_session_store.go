package fieldcrypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const (
	sessionSchemaVersion = 1
)

// RedisCryptoSessionStore stores session keys in Redis.
type RedisCryptoSessionStore struct {
	client    *goredis.Client
	namespace string
	ttl       time.Duration
}

// NewRedisCryptoSessionStore creates a Redis-backed store.
func NewRedisCryptoSessionStore(client *goredis.Client, namespace string, ttlSeconds int) *RedisCryptoSessionStore {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "get-loans"
	}
	if ttlSeconds <= 0 {
		ttlSeconds = defaultSessionTTL
	}
	return &RedisCryptoSessionStore{
		client:    client,
		namespace: ns,
		ttl:       time.Duration(ttlSeconds) * time.Second,
	}
}

func (s *RedisCryptoSessionStore) redisKey(sessionID string) string {
	return fmt.Sprintf("fcrypto:v1:%s:%s", s.namespace, sessionID)
}

func (s *RedisCryptoSessionStore) Put(sessionID string, key []byte) error {
	if len(key) != sessionKeyBytes {
		return fmt.Errorf("session key must be exactly 32 bytes")
	}
	now := time.Now().Unix()
	payload, err := json.Marshal(map[string]any{
		"schema_version":      sessionSchemaVersion,
		"crypto_session_id":   sessionID,
		"crypto_version":      cryptoVersion,
		"session_key_b64":     base64.StdEncoding.EncodeToString(key),
		"issued_at_epoch":     now,
		"expires_at_epoch":    now + int64(s.ttl.Seconds()),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := s.client.Set(ctx, s.redisKey(sessionID), payload, s.ttl).Err(); err != nil {
		return NewSessionStoreUnavailable()
	}
	return nil
}

func (s *RedisCryptoSessionStore) Get(sessionID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	raw, err := s.client.Get(ctx, s.redisKey(sessionID)).Bytes()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, NewSessionStoreUnavailable()
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	if intFromAny(data["schema_version"]) != sessionSchemaVersion {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	if fmt.Sprint(data["crypto_version"]) != cryptoVersion {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	if fmt.Sprint(data["crypto_session_id"]) != sessionID {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	if intFromAny(data["expires_at_epoch"]) <= int(time.Now().Unix()) {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	keyB64, ok := data["session_key_b64"].(string)
	if !ok {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != sessionKeyBytes {
		_ = s.Delete(sessionID)
		return nil, nil
	}
	return key, nil
}

func (s *RedisCryptoSessionStore) Delete(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := s.client.Del(ctx, s.redisKey(sessionID)).Err(); err != nil {
		return NewSessionStoreUnavailable()
	}
	return nil
}

func (s *RedisCryptoSessionStore) Revoke(sessionID string) error {
	return s.Delete(sessionID)
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return -1
	}
}

func redisClientFromEnv() (*goredis.Client, error) {
	url := strings.TrimSpace(os.Getenv("REDIS_URL"))
	if url == "" {
		return nil, fmt.Errorf("REDIS_URL must be set explicitly when CRYPTO_SESSION_BACKEND=redis")
	}
	opts, err := goredis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(os.Getenv("REDIS_SOCKET_CONNECT_TIMEOUT")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			opts.DialTimeout = time.Duration(f * float64(time.Second))
		}
	}
	if v := strings.TrimSpace(os.Getenv("REDIS_SOCKET_TIMEOUT")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			opts.ReadTimeout = time.Duration(f * float64(time.Second))
			opts.WriteTimeout = time.Duration(f * float64(time.Second))
		}
	}
	return goredis.NewClient(opts), nil
}
