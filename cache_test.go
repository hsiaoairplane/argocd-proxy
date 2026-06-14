package main

import (
	"bytes"
	"testing"
)

func TestResponseCacheGetPutInvalidate(t *testing.T) {
	c := NewResponseCache()

	if _, ok := c.Get("scope-1", 5); ok {
		t.Fatal("empty cache returned a hit")
	}

	body := []byte(`{"items":[]}`)
	entry := buildCacheEntry(body, 5)
	c.Put("scope-1", entry)

	got, ok := c.Get("scope-1", 5)
	if !ok {
		t.Fatal("expected hit after Put at same version")
	}
	if got.etag != entry.etag || !bytes.Equal(got.variant(encIdentity), body) {
		t.Error("cached entry mismatch")
	}
	if !bytes.Equal(got.variant(encGzip), compress(encGzip, body)) {
		t.Error("gzip variant not precomputed correctly")
	}

	// A newer store version invalidates the entry.
	if _, ok := c.Get("scope-1", 6); ok {
		t.Error("stale entry returned for newer version")
	}
}
