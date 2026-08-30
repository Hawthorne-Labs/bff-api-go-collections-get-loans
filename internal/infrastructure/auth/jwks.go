package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const jwksCacheTTL = time.Hour

type jwkDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksCache struct {
	url        string
	httpClient *http.Client
	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey
	fetchedAt  time.Time
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{
		url:        url,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       map[string]*rsa.PublicKey{},
	}
}

func (c *jwksCache) key(kid string) (*rsa.PublicKey, error) {
	if c.url == "" {
		return nil, fmt.Errorf("jwks url is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.fetchedAt) > jwksCacheTTL || len(c.keys) == 0 {
		if err := c.refreshLocked(); err != nil {
			if len(c.keys) == 0 {
				return nil, err
			}
		}
	}
	key, ok := c.keys[kid]
	if !ok {
		if err := c.refreshLocked(); err != nil {
			return nil, err
		}
		key, ok = c.keys[kid]
		if !ok {
			return nil, fmt.Errorf("jwks kid not found")
		}
	}
	return key, nil
}

func (c *jwksCache) refreshLocked() error {
	resp, err := c.httpClient.Get(c.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc jwkDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	next := map[string]*rsa.PublicKey{}
	for _, key := range doc.Keys {
		if key.Kty != "RSA" || key.Kid == "" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(key.N, key.E)
		if err != nil {
			continue
		}
		next[key.Kid] = pub
	}
	if len(next) == 0 {
		return fmt.Errorf("jwks contained no rsa keys")
	}
	c.keys = next
	c.fetchedAt = time.Now()
	return nil
}

func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e <= 0 {
		return nil, fmt.Errorf("invalid jwk exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
