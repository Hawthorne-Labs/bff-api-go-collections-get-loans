package auth

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	identityEmailCacheKeyPrefix    = "identity:sub-email:"
	identityNegativeCacheKeyPrefix = "identity:sub-negative:"
)

type RedisIdentityEmailCache struct {
	client *redis.Client
}

func NewIdentityEmailCache(redisURL string) IdentityEmailCache {
	if strings.TrimSpace(redisURL) == "" {
		return NewInMemoryTtlIdentityEmailCache()
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return NewInMemoryTtlIdentityEmailCache()
	}
	options.DialTimeout = 250 * time.Millisecond
	options.ReadTimeout = 500 * time.Millisecond
	options.WriteTimeout = 500 * time.Millisecond
	return &RedisIdentityEmailCache{client: redis.NewClient(options)}
}

func (c *RedisIdentityEmailCache) Get(subject string) string {
	if subject == "" || c == nil || c.client == nil {
		return ""
	}
	value, err := c.client.Get(context.Background(), identityEmailCacheKeyPrefix+subject).Result()
	if err != nil {
		return ""
	}
	return value
}

func (c *RedisIdentityEmailCache) Set(subject, email string) {
	if subject == "" || email == "" || c == nil || c.client == nil {
		return
	}
	_ = c.client.Set(context.Background(), identityEmailCacheKeyPrefix+subject, email, identityEmailCacheTTL).Err()
}

func (c *RedisIdentityEmailCache) IsNegative(subject string) bool {
	if subject == "" || c == nil || c.client == nil {
		return false
	}
	value, err := c.client.Get(context.Background(), identityNegativeCacheKeyPrefix+subject).Result()
	return err == nil && value != ""
}

func (c *RedisIdentityEmailCache) SetNegative(subject string) {
	if subject == "" || c == nil || c.client == nil {
		return
	}
	_ = c.client.Set(context.Background(), identityNegativeCacheKeyPrefix+subject, "1", identityNegativeCacheTTL).Err()
}
