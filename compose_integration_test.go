package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// End-to-end: many apps across several projects, composed admin response must
// decode to exactly the full set, across all encodings.
func TestComposedAdminCompleteness(t *testing.T) {
	store := NewAppStore()
	total := 0
	for _, proj := range []string{"team-a", "team-b", "team-c"} {
		for i := 0; i < 50; i++ {
			id := proj + "-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			store.Upsert(id, rawApp(id, proj, "https://c1", "ns"))
			total++
		}
	}
	fc := NewFragmentCache()

	for _, ae := range []string{"identity", "gzip", "zstd"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
		req.Header.Set("Accept-Encoding", ae)
		rec := httptest.NewRecorder()
		serveApplicationList(rec, req, store, fc, map[string]struct{}{"*": {}})

		enc := negotiateEncoding(ae)
		n := appCount(t, rec, enc)
		if n != total {
			t.Errorf("encoding %s: composed admin items = %d, want %d", ae, n, total)
		}
	}

	// A scoped user over two of the three projects sees exactly those.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rec := httptest.NewRecorder()
	serveApplicationList(rec, req, store, fc, map[string]struct{}{"team-a": {}, "team-c": {}})
	if n := appCount(t, rec, encIdentity); n != 100 {
		t.Errorf("two-project scope items = %d, want 100", n)
	}
}
