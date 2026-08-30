package auth

import (
	"sync"
	"time"
)

const (
	identityEmailCacheTTL      = 24 * time.Hour
	identityNegativeCacheTTL   = 120 * time.Second
	identityEmailCacheMaxEntries = 4096
)

// IdentityEmailCache stores sub→email mappings. Empty emails are never stored
// (anti-regresion: BUG-0662 ver handoffs/regressions.md).
type IdentityEmailCache interface {
	Get(subject string) string
	Set(subject, email string)
	IsNegative(subject string) bool
	SetNegative(subject string)
}

type cacheEntry struct {
	expiresAt time.Time
	email     string
}

// InMemoryTtlIdentityEmailCache is the process-local fallback when Redis is unavailable.
type InMemoryTtlIdentityEmailCache struct {
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int
	mu          sync.Mutex
	entries     map[string]cacheEntry
	negatives   map[string]time.Time
	order       []string
	negOrder    []string
}

func NewInMemoryTtlIdentityEmailCache() *InMemoryTtlIdentityEmailCache {
	return &InMemoryTtlIdentityEmailCache{
		ttl:         identityEmailCacheTTL,
		negativeTTL: identityNegativeCacheTTL,
		maxEntries:  identityEmailCacheMaxEntries,
		entries:     map[string]cacheEntry{},
		negatives:   map[string]time.Time{},
	}
}

func (c *InMemoryTtlIdentityEmailCache) Get(subject string) string {
	if subject == "" {
		return ""
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[subject]
	if !ok {
		return ""
	}
	if !entry.expiresAt.After(now) {
		delete(c.entries, subject)
		return ""
	}
	return entry.email
}

func (c *InMemoryTtlIdentityEmailCache) Set(subject, email string) {
	if subject == "" || email == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[subject]; !exists {
		c.order = append(c.order, subject)
	}
	c.entries[subject] = cacheEntry{expiresAt: time.Now().Add(c.ttl), email: email}
	for len(c.entries) > c.maxEntries && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

func (c *InMemoryTtlIdentityEmailCache) IsNegative(subject string) bool {
	if subject == "" {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	expiresAt, ok := c.negatives[subject]
	if !ok {
		return false
	}
	if !expiresAt.After(now) {
		delete(c.negatives, subject)
		return false
	}
	return true
}

func (c *InMemoryTtlIdentityEmailCache) SetNegative(subject string) {
	if subject == "" || c.negativeTTL <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.negatives[subject]; !exists {
		c.negOrder = append(c.negOrder, subject)
	}
	c.negatives[subject] = time.Now().Add(c.negativeTTL)
	for len(c.negatives) > c.maxEntries && len(c.negOrder) > 0 {
		oldest := c.negOrder[0]
		c.negOrder = c.negOrder[1:]
		delete(c.negatives, oldest)
	}
}
