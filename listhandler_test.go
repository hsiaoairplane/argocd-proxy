package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newListDeps() (*AppStore, *ResponseCache) {
	s := NewAppStore()
	s.Upsert("a", rawApp("a", "proj-a", "https://c1", "ns-1"))
	s.Upsert("b", rawApp("b", "proj-a", "https://c1", "ns-2"))
	return s, NewResponseCache()
}

func TestServeApplicationList(t *testing.T) {
	store, cache := newListDeps()
	patterns := map[string]struct{}{"*": {}}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	serveApplicationList(rec, req, store, cache, patterns)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	et := rec.Header().Get("ETag")
	if et == "" {
		t.Fatal("missing ETag")
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", enc)
	}
	if rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("missing Vary: Accept-Encoding")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req2.Header.Set("If-None-Match", et)
	rec2 := httptest.NewRecorder()
	serveApplicationList(rec2, req2, store, cache, patterns)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 body must be empty, got %d bytes", rec2.Body.Len())
	}

	store.Upsert("c", rawApp("c", "proj-b", "https://c1", "ns-1"))
	rec3 := httptest.NewRecorder()
	serveApplicationList(rec3, req2, store, cache, patterns)
	if rec3.Code != http.StatusOK {
		t.Errorf("status after change = %d, want 200", rec3.Code)
	}
}

func TestServeApplicationListReturnsFalseWhenEmpty(t *testing.T) {
	store := NewAppStore() // empty
	if served := serveApplicationList(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil),
		store, NewResponseCache(), map[string]struct{}{"*": {}}); served {
		t.Error("expected serveApplicationList to report not-served for empty scope")
	}
}
