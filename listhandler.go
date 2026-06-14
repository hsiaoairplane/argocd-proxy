package main

import "net/http"

// serveApplicationList writes the cached, precompressed application list for the
// caller's scope. It returns false (writing nothing) when the scope resolves to
// zero applications, so the caller can fall through to the backend proxy — this
// preserves the existing "empty cache -> proxy" behavior.
func serveApplicationList(w http.ResponseWriter, r *http.Request, store *AppStore, cache *ResponseCache, patterns map[string]struct{}) bool {
	q := r.URL.Query()
	cluster, namespace := q.Get("cluster"), q.Get("namespace")
	key := scopeKey(patterns, cluster, namespace)
	version := store.Version()

	entry, ok := cache.Get(key, version)
	if !ok {
		items := store.Items(patterns, cluster, namespace)
		if len(items) == 0 {
			return false
		}
		entry = buildCacheEntry(assembleItems(items), version)
		cache.Put(key, entry)
	}

	h := w.Header()
	h.Set("ETag", entry.etag)
	h.Set("Vary", "Accept-Encoding")
	h.Set("Content-Type", "application/json")

	if match := r.Header.Get("If-None-Match"); match == entry.etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	enc := negotiateEncoding(r.Header.Get("Accept-Encoding"))
	if hdr := enc.header(); hdr != "" {
		h.Set("Content-Encoding", hdr)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.variant(enc))
	return true
}
