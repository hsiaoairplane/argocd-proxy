package main

import (
	"bytes"
	"sync"
)

// fragment is one project's applications joined by commas (no {"items":[...]}
// envelope), precompressed in each encoding. version is the AppStore project
// version it was built from.
type fragment struct {
	version uint64
	raw     []byte
	gzip    []byte
	zstd    []byte
}

func (f *fragment) variant(enc encoding) []byte {
	switch enc {
	case encZstd:
		return f.zstd
	case encGzip:
		return f.gzip
	default:
		return f.raw
	}
}

// joinItems concatenates raw application JSON with commas and no envelope.
func joinItems(items [][]byte) []byte {
	if len(items) == 0 {
		return nil
	}
	var b bytes.Buffer
	for i, it := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(it)
	}
	return b.Bytes()
}

// FragmentCache caches one precompressed fragment per project, rebuilt lazily
// when the project's AppStore version changes.
type FragmentCache struct {
	mu    sync.RWMutex
	frags map[string]*fragment
}

func NewFragmentCache() *FragmentCache {
	return &FragmentCache{frags: make(map[string]*fragment)}
}

// Fragment returns the current fragment for a project, rebuilding it (outside
// the lock) if the cached one is stale.
func (c *FragmentCache) Fragment(store *AppStore, project string) *fragment {
	version := store.ProjectVersion(project)

	c.mu.RLock()
	cached, ok := c.frags[project]
	c.mu.RUnlock()
	if ok && cached.version == version {
		return cached
	}

	raw := joinItems(store.ProjectItems(project))
	built := &fragment{
		version: version,
		raw:     raw,
		gzip:    compress(encGzip, raw),
		zstd:    compress(encZstd, raw),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Another goroutine may have built a newer fragment meanwhile.
	if cur, ok := c.frags[project]; ok && cur.version >= built.version {
		return cur
	}
	c.frags[project] = built
	return built
}
