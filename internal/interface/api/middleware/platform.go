package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CORS handles Cross-Origin Resource Sharing (activity-log parity).
func CORS(origins string) gin.HandlerFunc {
	originList := parseOrigins(origins)
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := false
		for _, o := range originList {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			if origin != "" {
				c.Header("Access-Control-Allow-Origin", origin)
			} else {
				c.Header("Access-Control-Allow-Origin", "*")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Trace-Id, X-Tenant-Id, X-User-Email, X-Crypto-Session-Id, X-Crypto-Access-Token, Crypto-Session-Id, Crypto-Request-Id, Crypto-Version, Crypto-Tenant-Id, Idempotency-Key, traceparent")
			c.Header("Access-Control-Max-Age", "86400")
		}
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func parseOrigins(origins string) []string {
	if origins == "" {
		return []string{"*"}
	}
	result := []string{}
	for _, o := range strings.Split(origins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			result = append(result, o)
		}
	}
	if len(result) == 0 {
		return []string{"*"}
	}
	return result
}

// RateLimitStore decides whether a key may proceed.
type RateLimitStore interface {
	Allow(key string) bool
}

type memoryRateLimitStore struct {
	limit   int
	window  time.Duration
	mu      sync.Mutex
	entries map[string][]time.Time
}

// NewMemoryRateLimitStore creates an in-memory sliding window limiter.
func NewMemoryRateLimitStore(limit, windowSeconds int) RateLimitStore {
	if limit <= 0 {
		limit = 60
	}
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	return &memoryRateLimitStore{
		limit:   limit,
		window:  time.Duration(windowSeconds) * time.Second,
		entries: make(map[string][]time.Time),
	}
}

func (s *memoryRateLimitStore) Allow(key string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.entries[key][:0]
	for _, ts := range s.entries[key] {
		if now.Sub(ts) < s.window {
			active = append(active, ts)
		}
	}
	if len(active) >= s.limit {
		s.entries[key] = active
		return false
	}
	active = append(active, now)
	s.entries[key] = active
	return true
}

// RateLimitMiddleware applies per-IP+path limits.
func RateLimitMiddleware(store RateLimitStore, trustedProxies string, skipPrefixes string) gin.HandlerFunc {
	trusted := parseTrustedProxies(trustedProxies)
	skips := parseSkipPrefixes(skipPrefixes)
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		for _, prefix := range skips {
			if strings.HasPrefix(path, prefix) {
				c.Next()
				return
			}
		}
		clientIP := resolveClientIP(c.ClientIP(), c.GetHeader("X-Forwarded-For"), trusted)
		if store == nil || store.Allow(clientIP+":"+path) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": map[string]any{"code": 90008, "message": "Se excedió el límite de solicitudes."}})
	}
}

// RequestSizeLimitMiddleware rejects oversized bodies.
func RequestSizeLimitMiddleware(maxBytes int) gin.HandlerFunc {
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, int64(maxBytes))
		}
		c.Next()
	}
}

func parseTrustedProxies(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	return out
}

func parseSkipPrefixes(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func resolveClientIP(directHost, forwardedFor string, trusted map[string]struct{}) string {
	if !isTrustedProxy(directHost, trusted) || strings.TrimSpace(forwardedFor) == "" {
		return directHost
	}
	return strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
}

func isTrustedProxy(host string, trusted map[string]struct{}) bool {
	if _, ok := trusted[host]; ok {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for proxy := range trusted {
		if _, network, err := net.ParseCIDR(proxy); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
