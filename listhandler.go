package main

import "net/http"

// tryServeList intercepts the list endpoint for authenticated callers and serves
// it from the in-memory store. Returns false when the request is not an
// interceptable list call, or the token is missing/unparseable, or the caller's
// RBAC resolves to no patterns — in which case the caller falls through to the
// reverse proxy.
func tryServeList(w http.ResponseWriter, r *http.Request, store *AppStore, fc *FragmentCache, userToObjectPatternMapping, groupToObjectPatternMapping map[string][]string) bool {
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
	return serveApplicationList(w, r, store, fc, patterns)
}

// serveApplicationList serves the application list for the caller's scope. A
// cluster/namespace filter is computed on demand (small result); an unfiltered
// scope is composed from per-project precompressed fragments.
func serveApplicationList(w http.ResponseWriter, r *http.Request, store *AppStore, fc *FragmentCache, patterns map[string]struct{}) bool {
	q := r.URL.Query()
	cluster, namespace := q.Get("cluster"), q.Get("namespace")
	if cluster != "" || namespace != "" {
		return serveFiltered(w, r, store, patterns, cluster, namespace)
	}
	return serveComposed(w, r, store, fc, patterns)
}

// serveComposed streams the unfiltered scope by concatenating per-project
// precompressed fragments. It returns false (fall through) only when the scope
// contains no projects at all (e.g. an empty store under a "*" pattern).
func serveComposed(w http.ResponseWriter, r *http.Request, store *AppStore, fc *FragmentCache, patterns map[string]struct{}) bool {
	projects := resolveProjects(patterns, store)
	if len(projects) == 0 {
		return false
	}

	etag := composeETag(store, projects)
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Vary", "Accept-Encoding")
	h.Set("Content-Type", "application/json")

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	enc := negotiateEncoding(r.Header.Get("Accept-Encoding"))
	if hdr := enc.header(); hdr != "" {
		h.Set("Content-Encoding", hdr)
	}
	w.WriteHeader(http.StatusOK)
	writeComposedList(w, enc, store, fc, projects)
	return true
}

// serveFiltered handles a cluster/namespace-filtered query by computing the
// (small) result on demand. An empty result returns 200 {"items":[]} rather than
// falling through to the backend, which ignores these filters.
func serveFiltered(w http.ResponseWriter, r *http.Request, store *AppStore, patterns map[string]struct{}, cluster, namespace string) bool {
	body := assembleItems(store.Items(patterns, cluster, namespace))
	et := etag(body)

	h := w.Header()
	h.Set("ETag", et)
	h.Set("Vary", "Accept-Encoding")
	h.Set("Content-Type", "application/json")

	if r.Header.Get("If-None-Match") == et {
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	enc := negotiateEncoding(r.Header.Get("Accept-Encoding"))
	if hdr := enc.header(); hdr != "" {
		h.Set("Content-Encoding", hdr)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(compress(enc, body))
	return true
}
