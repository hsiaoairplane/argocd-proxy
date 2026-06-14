package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newListStore() (*AppStore, *FragmentCache) {
	s := NewAppStore()
	s.Upsert("a", rawApp("a", "team-a", "https://c1", "ns-1"))
	s.Upsert("b", rawApp("b", "team-a", "https://c1", "ns-2"))
	s.Upsert("c", rawApp("c", "team-b", "https://c1", "ns-3"))
	return s, NewFragmentCache()
}

func appCount(t *testing.T, rec *httptest.ResponseRecorder, enc encoding) int {
	t.Helper()
	body := decodeForTest(t, enc, rec.Body.Bytes())
	var decoded struct {
		Items []map[string]any `json:"items"`
	}
	if err := jsonUnmarshalForTest(body, &decoded); err != nil {
		t.Fatalf("invalid body: %v (%s)", err, body)
	}
	return len(decoded.Items)
}

func jsonUnmarshalForTest(b []byte, v any) error { return json.Unmarshal(b, v) }

func TestServeApplicationListComposed(t *testing.T) {
	store, fc := newListStore()

	// admin ("*") sees all 3, with ETag + Content-Encoding + Vary.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	if !serveApplicationList(rec, req, store, fc, map[string]struct{}{"*": {}}) {
		t.Fatal("admin scope must be served")
	}
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" ||
		rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("bad response headers: code=%d etag=%q ce=%q vary=%q",
			rec.Code, rec.Header().Get("ETag"), rec.Header().Get("Content-Encoding"), rec.Header().Get("Vary"))
	}
	if n := appCount(t, rec, encGzip); n != 3 {
		t.Errorf("admin items = %d, want 3", n)
	}
	et := rec.Header().Get("ETag")

	// Conditional re-request: 304, empty body.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req2.Header.Set("If-None-Match", et)
	rec2 := httptest.NewRecorder()
	serveApplicationList(rec2, req2, store, fc, map[string]struct{}{"*": {}})
	if rec2.Code != http.StatusNotModified || rec2.Body.Len() != 0 {
		t.Fatalf("expected 304 empty, got %d (%d bytes)", rec2.Code, rec2.Body.Len())
	}

	// A change to team-b changes the admin ETag.
	store.Upsert("d", rawApp("d", "team-b", "https://c1", "ns-4"))
	rec3 := httptest.NewRecorder()
	serveApplicationList(rec3, req2, store, fc, map[string]struct{}{"*": {}})
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 after change, got %d", rec3.Code)
	}

	// team-a scope sees only its 2 apps.
	reqT := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	recT := httptest.NewRecorder()
	serveApplicationList(recT, reqT, store, fc, map[string]struct{}{"team-a": {}})
	if n := appCount(t, recT, encIdentity); n != 2 {
		t.Errorf("team-a items = %d, want 2", n)
	}
}

func TestServeApplicationListFiltered(t *testing.T) {
	store, fc := newListStore()
	patterns := map[string]struct{}{"*": {}}

	// Namespace filter -> subset.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications?namespace=ns-2", nil)
	rec := httptest.NewRecorder()
	if !serveApplicationList(rec, req, store, fc, patterns) {
		t.Fatal("filtered query must be served")
	}
	if n := appCount(t, rec, encIdentity); n != 1 {
		t.Errorf("filtered items = %d, want 1", n)
	}

	// Empty filter result -> 200 {"items":[]}, not fall-through.
	reqE := httptest.NewRequest(http.MethodGet, "/api/v1/applications?namespace=nope", nil)
	recE := httptest.NewRecorder()
	if served := serveApplicationList(recE, reqE, store, fc, patterns); !served {
		t.Fatal("empty filtered query must be served, not fall through")
	}
	if recE.Code != http.StatusOK || recE.Body.String() != `{"items":[]}` {
		t.Errorf("empty filter = %d %q, want 200 {\"items\":[]}", recE.Code, recE.Body.String())
	}
}
