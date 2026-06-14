package main

import "sync"

type cacheEntry struct {
	version  uint64
	etag     string
	identity []byte
	gzip     []byte
	zstd     []byte
}

func (e *cacheEntry) variant(enc encoding) []byte {
	switch enc {
	case encZstd:
		return e.zstd
	case encGzip:
		return e.gzip
	default:
		return e.identity
	}
}

// buildCacheEntry precompresses the body in all supported encodings and computes
// its ETag, so the request path only has to pick a variant and write it.
func buildCacheEntry(body []byte, version uint64) *cacheEntry {
	return &cacheEntry{
		version:  version,
		etag:     etag(body),
		identity: body,
		gzip:     compress(encGzip, body),
		zstd:     compress(encZstd, body),
	}
}

// ResponseCache maps a scope key to its precompressed response. Entries are
// considered fresh only when their version matches the requested store version.
type ResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

func NewResponseCache() *ResponseCache {
	return &ResponseCache{entries: make(map[string]*cacheEntry)}
}

func (c *ResponseCache) Get(key string, version uint64) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || e.version != version {
		return nil, false
	}
	return e, true
}

func (c *ResponseCache) Put(key string, e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}
