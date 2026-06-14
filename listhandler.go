package main

import "net/http"

// tryServeList intercepts the list endpoint for authenticated callers and serves
// it from the store/cache. It returns false when the request is not an
// interceptable list call, the token is missing/unparseable, or the scope is
// empty — in all those cases the caller falls through to the reverse proxy.
func tryServeList(w http.ResponseWriter, r *http.Request, store *AppStore, cache *ResponseCache, userToObjectPatternMapping, groupToObjectPatternMapping map[string][]string) bool {
	token := extractToken(r)
	if token == "" || !shouldInterceptListRequest(r) {
		return false
	}
	payload, err := decodeJWTPayload(token)
	if err != nil {
		return false
	}
	email, _ := payload["email"].(string)
	groups := extractGroups(payload)
	patterns := resolveObjectPatterns(email, groups, userToObjectPatternMapping, groupToObjectPatternMapping)
	if len(patterns) == 0 {
		return false
	}
	return serveApplicationList(w, r, store, cache, patterns)
}

// serveApplicationList writes the cached, precompressed application list for the
// caller's scope. It returns false (writing nothing) only for an *unfiltered*
// query that resolves to zero applications, so the caller can fall through to the
// backend proxy — preserving the original "empty cache -> proxy" behavior. A
// cluster/namespace filter that matches nothing is instead a valid empty result
// ({"items":[]}): falling through there would let the backend ignore the filter
// and return the full list.
func serveApplicationList(w http.ResponseWriter, r *http.Request, store *AppStore, cache *ResponseCache, patterns map[string]struct{}) bool {
	q := r.URL.Query()
	cluster, namespace := q.Get("cluster"), q.Get("namespace")
	filtered := cluster != "" || namespace != ""
	key := scopeKey(patterns, cluster, namespace)
	version := store.Version()

	entry, ok := cache.Get(key, version)
	if !ok {
		items := store.Items(patterns, cluster, namespace)
		if len(items) == 0 && !filtered {
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
