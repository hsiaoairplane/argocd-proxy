# Fast application-list proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve `GET /api/v1/applications` from an in-process, informer-fed store with per-scope precompressed (zstd+gzip) + ETagged responses, removing Redis and per-request assembly/compression from the read path.

**Architecture:** A k8s dynamic informer keeps a thread-safe in-memory `AppStore` of trimmed application JSON bytes, indexed by project/namespace/cluster, with a monotonic version. A `ResponseCache` keyed by request scope holds assembled `{"items":[...]}` bodies precompressed in identity/gzip/zstd plus an ETag, invalidated by version. The list handler resolves the caller's RBAC scope, serves the precompressed variant matching `Accept-Encoding`, and answers `If-None-Match` with `304`. All non-list requests pass through to argocd-server unchanged.

**Tech Stack:** Go, `k8s.io/client-go/dynamic` + `dynamicinformer`, `github.com/klauspost/compress/zstd`, stdlib `compress/gzip`, `net/http`.

**Base:** Builds on `main` after PR #75 (which added `fetchRawApplications` / `writeApplicationList` / `filterRawByClusterAndNamespace`). This plan removes `fetchRawApplications` (Redis) and reuses the envelope-writing idea inside the new cache.

**Spec:** `docs/superpowers/specs/2026-06-14-fast-list-proxy-design.md`

---

## File structure

- Create `compress.go` — encoding negotiation + zstd/gzip helpers (pure functions).
- Create `store.go` — `AppStore`: in-memory apps, indexes, version, scope query.
- Create `scope.go` — deterministic scope key + item selection from the store.
- Create `cache.go` — `ResponseCache`: per-scope assembled body, ETag, precompressed variants, version invalidation.
- Create `listhandler.go` — `serveApplicationList`: scope → cache → negotiation → 304/200.
- Create `informer.go` — dynamic informer wiring that drives `AppStore`.
- Modify `main.go` — start the informer + store, drop Redis from the read path, route the list endpoint through `serveApplicationList`.
- Remove from `main.go` (post-cutover): `fetchRawApplications`, the Redis client on the read path, `filterRawByClusterAndNamespace` moves into `scope.go`.

---

## Task 1: Add zstd dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the module**

Run: `go get github.com/klauspost/compress@latest`
Expected: `go.mod` gains a `github.com/klauspost/compress` require line.

- [ ] **Step 2: Verify it builds**

Run: `go build ./...`
Expected: success, no errors.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add klauspost/compress for zstd"
```

---

## Task 2: Encoding negotiation

**Files:**
- Create: `compress.go`
- Test: `compress_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestNegotiateEncoding(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   encoding
	}{
		{"zstd preferred", "gzip, deflate, zstd", encZstd},
		{"gzip when no zstd", "gzip, deflate", encGzip},
		{"identity when none", "deflate, br", encIdentity},
		{"empty header", "", encIdentity},
		{"zstd only", "zstd", encZstd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := negotiateEncoding(tt.header); got != tt.want {
				t.Errorf("negotiateEncoding(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestNegotiateEncoding`
Expected: FAIL — `undefined: negotiateEncoding` / `encoding`.

- [ ] **Step 3: Write minimal implementation**

```go
package main

import "strings"

type encoding int

const (
	encIdentity encoding = iota
	encGzip
	encZstd
)

func (e encoding) header() string {
	switch e {
	case encZstd:
		return "zstd"
	case encGzip:
		return "gzip"
	default:
		return ""
	}
}

// negotiateEncoding picks the best response encoding the client accepts,
// preferring zstd, then gzip, then identity. Quality values are ignored; a
// token is treated as accepted if it appears at all.
func negotiateEncoding(acceptEncoding string) encoding {
	tokens := make(map[string]bool)
	for _, part := range strings.Split(acceptEncoding, ",") {
		name := strings.TrimSpace(part)
		if i := strings.IndexByte(name, ';'); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		if name != "" {
			tokens[strings.ToLower(name)] = true
		}
	}
	switch {
	case tokens["zstd"]:
		return encZstd
	case tokens["gzip"]:
		return encGzip
	default:
		return encIdentity
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestNegotiateEncoding`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add compress.go compress_test.go
git commit -m "feat: add response encoding negotiation"
```

---

## Task 3: Compression helpers

**Files:**
- Modify: `compress.go`
- Test: `compress_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestCompressRoundTrip(t *testing.T) {
	payload := []byte(`{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`)

	gz := compress(encGzip, payload)
	if len(gz) == 0 {
		t.Fatal("gzip produced empty output")
	}
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, _ := io.ReadAll(gr)
	if !bytes.Equal(got, payload) {
		t.Errorf("gzip round-trip mismatch")
	}

	zs := compress(encZstd, payload)
	dec, _ := zstd.NewReader(nil)
	gotZ, err := dec.DecodeAll(zs, nil)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}
	if !bytes.Equal(gotZ, payload) {
		t.Errorf("zstd round-trip mismatch")
	}

	if id := compress(encIdentity, payload); !bytes.Equal(id, payload) {
		t.Errorf("identity must return input unchanged")
	}
}
```

Add imports to `compress_test.go`: `"bytes"`, `"compress/gzip"`, `"io"`, `"github.com/klauspost/compress/zstd"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestCompressRoundTrip`
Expected: FAIL — `undefined: compress`.

- [ ] **Step 3: Write minimal implementation (append to compress.go)**

```go
import (
	"bytes"
	"compress/gzip"

	"github.com/klauspost/compress/zstd"
)

// zstdEncoder is safe for concurrent use via EncodeAll.
var zstdEncoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))

// compress returns data encoded with enc. encIdentity returns data unchanged.
func compress(enc encoding, data []byte) []byte {
	switch enc {
	case encZstd:
		return zstdEncoder.EncodeAll(data, make([]byte, 0, len(data)/3))
	case encGzip:
		var buf bytes.Buffer
		gw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		_, _ = gw.Write(data)
		_ = gw.Close()
		return buf.Bytes()
	default:
		return data
	}
}
```

Merge the `strings` import from Task 2 with this import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestCompressRoundTrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add compress.go compress_test.go
git commit -m "feat: add gzip/zstd compression helpers"
```

---

## Task 4: AppStore — upsert, delete, version

**Files:**
- Create: `store.go`
- Test: `store_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func rawApp(name, project, server, namespace string) []byte {
	return []byte(`{"metadata":{"name":"` + name + `"},"spec":{"project":"` + project +
		`","destination":{"server":"` + server + `","namespace":"` + namespace + `"}}}`)
}

func TestAppStoreUpsertDeleteVersion(t *testing.T) {
	s := NewAppStore()
	if s.Version() != 0 {
		t.Fatalf("initial version = %d, want 0", s.Version())
	}

	s.Upsert("app-1", rawApp("app-1", "proj-a", "https://c1", "ns-1"))
	if got := s.Version(); got != 1 {
		t.Errorf("version after first upsert = %d, want 1", got)
	}

	// Re-upsert with identical bytes must NOT bump the version.
	s.Upsert("app-1", rawApp("app-1", "proj-a", "https://c1", "ns-1"))
	if got := s.Version(); got != 1 {
		t.Errorf("version after no-op upsert = %d, want 1", got)
	}

	// Changed bytes bump the version.
	s.Upsert("app-1", rawApp("app-1", "proj-a", "https://c1", "ns-2"))
	if got := s.Version(); got != 2 {
		t.Errorf("version after changed upsert = %d, want 2", got)
	}

	s.Delete("app-1")
	if got := s.Version(); got != 3 {
		t.Errorf("version after delete = %d, want 3", got)
	}
	// Deleting a missing key is a no-op for the version.
	s.Delete("app-1")
	if got := s.Version(); got != 3 {
		t.Errorf("version after no-op delete = %d, want 3", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestAppStoreUpsertDeleteVersion`
Expected: FAIL — `undefined: NewAppStore`.

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
	"bytes"
	"sync"
)

type appEntry struct {
	raw       []byte
	project   string
	cluster   string // spec.destination.server
	clusterNm string // spec.destination.name
	namespace string // spec.destination.namespace
}

// AppStore is a concurrency-safe, in-memory mirror of application objects keyed
// by a stable id (the application name). version increments on every mutation
// that actually changes stored content, so caches can detect staleness cheaply.
type AppStore struct {
	mu      sync.RWMutex
	apps    map[string]appEntry
	version uint64
}

func NewAppStore() *AppStore {
	return &AppStore{apps: make(map[string]appEntry)}
}

func (s *AppStore) Version() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *AppStore) Upsert(id string, raw []byte) {
	entry := parseAppEntry(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.apps[id]; ok && bytes.Equal(old.raw, entry.raw) {
		return
	}
	s.apps[id] = entry
	s.version++
}

func (s *AppStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apps[id]; !ok {
		return
	}
	delete(s.apps, id)
	s.version++
}
```

- [ ] **Step 4: Add the entry parser (append to store.go)**

```go
import "encoding/json"

func parseAppEntry(raw []byte) appEntry {
	var meta struct {
		Spec struct {
			Project     string `json:"project"`
			Destination struct {
				Server    string `json:"server"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"destination"`
		} `json:"spec"`
	}
	_ = json.Unmarshal(raw, &meta) // best-effort; missing fields stay empty
	return appEntry{
		raw:       raw,
		project:   meta.Spec.Project,
		cluster:   meta.Spec.Destination.Server,
		clusterNm: meta.Spec.Destination.Name,
		namespace: meta.Spec.Destination.Namespace,
	}
}
```

Merge the `encoding/json` import with the existing import block.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./... -run TestAppStoreUpsertDeleteVersion`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add store.go store_test.go
git commit -m "feat: add in-memory AppStore with versioning"
```

---

## Task 5: AppStore — scope query

**Files:**
- Modify: `store.go`
- Test: `store_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestAppStoreItems(t *testing.T) {
	s := NewAppStore()
	s.Upsert("a", rawApp("a", "proj-a", "https://c1", "ns-1"))
	s.Upsert("b", rawApp("b", "proj-a", "https://c2", "ns-2"))
	s.Upsert("c", rawApp("c", "proj-b", "https://c1", "ns-1"))

	count := func(patterns map[string]struct{}, cluster, ns string) int {
		return len(s.Items(patterns, cluster, ns))
	}

	// Wildcard pattern returns everything.
	if n := count(map[string]struct{}{"*": {}}, "", ""); n != 3 {
		t.Errorf("wildcard count = %d, want 3", n)
	}
	// Single project.
	if n := count(map[string]struct{}{"proj-a": {}}, "", ""); n != 2 {
		t.Errorf("proj-a count = %d, want 2", n)
	}
	// Project + namespace filter.
	if n := count(map[string]struct{}{"proj-a": {}}, "", "ns-1"); n != 1 {
		t.Errorf("proj-a/ns-1 count = %d, want 1", n)
	}
	// Project + cluster filter.
	if n := count(map[string]struct{}{"*": {}}, "https://c1", ""); n != 2 {
		t.Errorf("cluster c1 count = %d, want 2", n)
	}
	// No matching pattern.
	if n := count(map[string]struct{}{"proj-x": {}}, "", ""); n != 0 {
		t.Errorf("proj-x count = %d, want 0", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestAppStoreItems`
Expected: FAIL — `s.Items undefined`.

- [ ] **Step 3: Write minimal implementation (append to store.go)**

```go
import "sort"

// Items returns the raw JSON of every stored application whose project matches
// one of patterns (the literal "*" matches all projects) and, when non-empty,
// whose destination matches cluster and namespace. Results are sorted by id for
// deterministic output (stable ETags).
func (s *AppStore) Items(patterns map[string]struct{}, cluster, namespace string) [][]byte {
	_, all := patterns["*"]

	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.apps))
	for id, e := range s.apps {
		if !all {
			if _, ok := patterns[e.project]; !ok {
				continue
			}
		}
		if cluster != "" && e.cluster != cluster && e.clusterNm != cluster {
			continue
		}
		if namespace != "" && e.namespace != namespace {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)

	items := make([][]byte, len(ids))
	for i, id := range ids {
		items[i] = s.apps[id].raw
	}
	return items
}
```

Merge `sort` into the import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestAppStoreItems`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add store.go store_test.go
git commit -m "feat: add AppStore scope query with project/cluster/namespace filtering"
```

---

## Task 6: Scope key

**Files:**
- Create: `scope.go`
- Test: `scope_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestScopeKey(t *testing.T) {
	// Pattern set order must not change the key.
	k1 := scopeKey(map[string]struct{}{"a": {}, "b": {}}, "", "")
	k2 := scopeKey(map[string]struct{}{"b": {}, "a": {}}, "", "")
	if k1 != k2 {
		t.Errorf("scopeKey not order-independent: %q vs %q", k1, k2)
	}
	// Different filters must produce different keys.
	if scopeKey(map[string]struct{}{"a": {}}, "c1", "") == scopeKey(map[string]struct{}{"a": {}}, "c2", "") {
		t.Error("different cluster produced same key")
	}
	if scopeKey(map[string]struct{}{"a": {}}, "", "n1") == scopeKey(map[string]struct{}{"a": {}}, "", "n2") {
		t.Error("different namespace produced same key")
	}
	// A pattern value containing the delimiter must not collide.
	if scopeKey(map[string]struct{}{"a,b": {}}, "", "") == scopeKey(map[string]struct{}{"a": {}, "b": {}}, "", "") {
		t.Error("delimiter collision between {'a,b'} and {'a','b'}")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestScopeKey`
Expected: FAIL — `undefined: scopeKey`.

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
	"sort"
	"strconv"
	"strings"
)

// scopeKey builds a deterministic cache key from the caller's allowed project
// patterns and the optional cluster/namespace filters. Each pattern is
// length-prefixed so values containing the delimiter cannot collide.
func scopeKey(patterns map[string]struct{}, cluster, namespace string) string {
	ps := make([]string, 0, len(patterns))
	for p := range patterns {
		ps = append(ps, p)
	}
	sort.Strings(ps)

	var b strings.Builder
	for _, p := range ps {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
		b.WriteByte('|')
	}
	b.WriteString("\x1ecluster=")
	b.WriteString(cluster)
	b.WriteString("\x1ens=")
	b.WriteString(namespace)
	return b.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestScopeKey`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scope.go scope_test.go
git commit -m "feat: add deterministic scope key"
```

---

## Task 7: Body assembly + ETag

**Files:**
- Modify: `scope.go`
- Test: `scope_test.go`

- [ ] **Step 1: Write the failing test**

```go
import (
	"bytes"
	"encoding/json"
)

func TestAssembleItems(t *testing.T) {
	items := [][]byte{[]byte(`{"metadata":{"name":"a"}}`), []byte(`{"metadata":{"name":"b"}}`)}
	body := assembleItems(items)

	want := `{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`
	if string(body) != want {
		t.Errorf("assembleItems = %s, want %s", body, want)
	}
	var decoded struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Items) != 2 || !bytes.Equal(decoded.Items[0], items[0]) {
		t.Errorf("items not preserved verbatim")
	}
	if assembleItems(nil); string(assembleItems(nil)) != `{"items":[]}` {
		t.Errorf("empty assemble = %s, want {\"items\":[]}", assembleItems(nil))
	}
}

func TestETagStability(t *testing.T) {
	a := etag([]byte(`{"items":[1]}`))
	if a != etag([]byte(`{"items":[1]}`)) {
		t.Error("etag not stable for identical input")
	}
	if a == etag([]byte(`{"items":[2]}`)) {
		t.Error("etag collided for different input")
	}
	if len(a) < 2 || a[0] != '"' || a[len(a)-1] != '"' {
		t.Errorf("etag must be a quoted string, got %s", a)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestAssembleItems|TestETagStability'`
Expected: FAIL — `undefined: assembleItems` / `etag`.

- [ ] **Step 3: Write minimal implementation (append to scope.go)**

```go
import (
	"hash/fnv"
	"strconv"
)

// assembleItems builds the {"items":[...]} envelope by concatenating the raw
// application bytes directly — no per-item marshaling.
func assembleItems(items [][]byte) []byte {
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i, raw := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(raw)
	}
	b.WriteString("]}")
	return []byte(b.String())
}

// etag returns a strong, quoted ETag derived from the uncompressed body.
func etag(body []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(body)
	return `"` + strconv.FormatUint(h.Sum64(), 16) + `"`
}
```

(`strconv` is already imported in scope.go from Task 6; add `hash/fnv`. `b.Write` on `strings.Builder` accepts `[]byte`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run 'TestAssembleItems|TestETagStability'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scope.go scope_test.go
git commit -m "feat: add items envelope assembly and ETag"
```

---

## Task 8: ResponseCache

**Files:**
- Create: `cache.go`
- Test: `cache_test.go`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestResponseCacheGetPutInvalidate`
Expected: FAIL — `undefined: NewResponseCache` etc.

- [ ] **Step 3: Write minimal implementation**

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestResponseCacheGetPutInvalidate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cache.go cache_test.go
git commit -m "feat: add per-scope precompressed response cache"
```

---

## Task 9: List handler

**Files:**
- Create: `listhandler.go`
- Test: `listhandler_test.go`

- [ ] **Step 1: Write the failing test**

```go
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

	// First request: 200 with body, ETag, and (gzip) Content-Encoding.
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

	// Conditional re-request with matching ETag: 304, empty body.
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

	// After a store change the ETag changes and a 200 is served again.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestServeApplicationList`
Expected: FAIL — `undefined: serveApplicationList`.

- [ ] **Step 3: Write minimal implementation**

```go
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
```

Note: when `cache.Get` misses but `Items` is empty we return false. There is a benign race where the version advances between `store.Version()` and `store.Items()`; the entry is then cached under a slightly stale version and simply rebuilt on the next request. Acceptable under the global-version model.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestServeApplicationList`
Expected: PASS (both list tests).

- [ ] **Step 5: Commit**

```bash
git add listhandler.go listhandler_test.go
git commit -m "feat: add cached list handler with ETag/304 and content negotiation"
```

---

## Task 10: Informer wiring

**Files:**
- Create: `informer.go`
- Test: `informer_test.go`

- [ ] **Step 1: Write the failing test (tombstone/object extraction helper)**

```go
package main

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func TestAppIDAndRaw(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "my-app"},
		"spec":     map[string]interface{}{"project": "p"},
	}}
	id, raw, ok := appIDAndRaw(u)
	if !ok || id != "my-app" || len(raw) == 0 {
		t.Fatalf("appIDAndRaw(u) = %q,%q,%v", id, raw, ok)
	}

	// managedFields must be stripped from the stored bytes.
	u2 := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "x", "managedFields": []interface{}{map[string]interface{}{"manager": "argocd"}}},
	}}
	_, raw2, _ := appIDAndRaw(u2)
	if bytesContains(raw2, "managedFields") {
		t.Error("managedFields not stripped")
	}

	// Tombstone unwrapping for deletes.
	tomb := cache.DeletedFinalStateUnknown{Key: "k", Obj: u}
	if _, _, ok := appIDAndRaw(tomb); !ok {
		t.Error("failed to unwrap DeletedFinalStateUnknown")
	}
}

func bytesContains(b []byte, s string) bool { return string(b) != "" && indexOf(string(b), s) >= 0 }
func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestAppIDAndRaw`
Expected: FAIL — `undefined: appIDAndRaw`.

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// appIDAndRaw extracts the store id (application name) and the trimmed JSON
// bytes for an informer event object, unwrapping delete tombstones. It strips
// metadata.managedFields, mirroring what argocd-watcher stores.
func appIDAndRaw(obj interface{}) (string, []byte, bool) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		t, isTomb := obj.(cache.DeletedFinalStateUnknown)
		if !isTomb {
			return "", nil, false
		}
		if u, ok = t.Obj.(*unstructured.Unstructured); !ok {
			return "", nil, false
		}
	}
	u = u.DeepCopy()
	unstructured.RemoveNestedField(u.Object, "metadata", "managedFields")
	raw, err := json.Marshal(u.Object)
	if err != nil {
		return "", nil, false
	}
	return u.GetName(), raw, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestAppIDAndRaw`
Expected: PASS.

- [ ] **Step 5: Add the informer starter (append to informer.go)**

```go
import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	log "github.com/sirupsen/logrus"
)

var applicationGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "applications",
}

// startApplicationInformer launches a dynamic informer that keeps store in sync
// with Application objects in namespace, and blocks until the cache is synced.
func startApplicationInformer(ctx context.Context, client dynamic.Interface, namespace string, resync time.Duration, store *AppStore) error {
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(client, resync, namespace, nil)
	informer := factory.ForResource(applicationGVR).Informer()

	upsert := func(obj interface{}) {
		if id, raw, ok := appIDAndRaw(obj); ok {
			store.Upsert(id, raw)
		}
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    upsert,
		UpdateFunc: func(_, newObj interface{}) { upsert(newObj) },
		DeleteFunc: func(obj interface{}) {
			if id, _, ok := appIDAndRaw(obj); ok {
				store.Delete(id)
			}
		},
	}); err != nil {
		return err
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return context.Canceled
	}
	log.Infoln("Application informer cache synced")
	return nil
}

var _ = metav1.ListOptions{} // imported for parity with watcher patterns; remove if unused
```

Remove the trailing `var _` line if `go vet` flags the unused `metav1` import; it is included only as a reminder and can be dropped.

- [ ] **Step 6: Verify build + tests**

Run: `go build ./... && go test ./... -run TestAppIDAndRaw`
Expected: build OK, test PASS.

- [ ] **Step 7: Commit**

```bash
git add informer.go informer_test.go
git commit -m "feat: add Application informer feeding the in-memory store"
```

---

## Task 11: Wire into main, drop Redis from the read path

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Replace Redis read wiring with store + informer in `main()`**

In `main.go`, remove the `redisAddr`/`redisDB` flags and `initializeRedis` call used for the read path, and add a `--resync-period` flag. After `config := ctrl.GetConfigOrDie()` and the existing clientset creation, add:

```go
dynamicClient := dynamic.NewForConfigOrDie(config)
store := NewAppStore()
cacheStore := NewResponseCache()

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

if err := startApplicationInformer(ctx, dynamicClient, *namespace, *resyncPeriod, store); err != nil {
	log.Fatalf("Failed to start application informer: %v", err)
}
```

Add imports: `"k8s.io/client-go/dynamic"`. Reuse the existing `context`, `signal`, `syscall`, `time` imports. Remove `"github.com/go-redis/redis/v7"` once no longer referenced (see Task 12).

- [ ] **Step 2: Route the list endpoint through the new handler**

Replace the body of the mux `"/"` handler so the interception uses the store/cache:

```go
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	if served := tryServeList(rw, r, store, cacheStore, userToObjectPatternMapping, groupToObjectPatternMapping); !served {
		proxy.ServeHTTP(rw, r)
	}

	duration := float64(time.Since(start).Milliseconds())
	statusCodeStr := fmt.Sprintf("%d", rw.statusCode)
	requestTotal.WithLabelValues(r.Method, r.URL.Path, statusCodeStr).Inc()
	requestDuration.WithLabelValues(r.Method, r.URL.Path, statusCodeStr).Observe(duration)
})
```

- [ ] **Step 3: Add `tryServeList` to `listhandler.go`**

```go
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
```

- [ ] **Step 4: Update readiness probe**

Replace the Redis ping in `/readyz` with informer freshness — readiness once the store has been populated at least once (version observed) is sufficient; keep it simple:

```go
mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})
```

- [ ] **Step 5: Build**

Run: `go build ./...`
Expected: success (fix any leftover Redis references per Task 12 if the build complains).

- [ ] **Step 6: Commit**

```bash
git add main.go listhandler.go
git commit -m "feat: serve list from informer-backed store, drop Redis from read path"
```

---

## Task 12: Remove dead Redis read-path code

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Delete now-unused functions and references**

Remove `fetchRawApplications`, `filterRawByClusterAndNamespace` (its logic now lives in `AppStore.Items`), `scanKeys`, `initializeRedis`, `handleRequest`, and the `redis` import and `redisClient` parameter threading — anything only used by the old Redis read path. Keep `extractToken`, `decodeJWTPayload`, `extractGroups`, `resolveObjectPatterns`, `parsePolicyCSV`, `shouldInterceptListRequest`, `createReverseProxy`, `loadRBACPolicyFromConfigMap`.

- [ ] **Step 2: Verify nothing references removed symbols**

Run: `go build ./... && go vet ./...`
Expected: success, no "declared and not used" or undefined errors.

- [ ] **Step 3: Run the full test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 4: Format**

Run: `gofmt -l .`
Expected: no files listed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: remove dead Redis read-path code"
```

---

## Task 13: End-to-end smoke test against the bench cluster (optional, manual)

**Files:** none (operational verification)

- [ ] **Step 1: Build and push the image**

Build `argocd-proxy` for linux/amd64 and push to the registry the cluster pulls from (mirrors the bench setup). Update the `argocd-proxy` Deployment to the new tag and remove the `--redis-addr`/`--redis-db` args.

- [ ] **Step 2: Verify correctness**

Confirm the admin and RBAC-restricted tokens return the same app counts as before, that responses carry `ETag` and `Content-Encoding`, and that a second request with `If-None-Match` returns `304`.

- [ ] **Step 3: Re-run the fortio benchmark**

Re-run the admin and team-a scenarios; expect repeat-scope latency to drop toward memcpy cost and unchanged-data conditional requests to return 304.

---

## Self-review notes

- **Spec coverage:** in-memory store (Tasks 4–5, 10), per-scope precompressed cache (Tasks 3, 8), ETag/304 (Tasks 7, 9), Accept-Encoding negotiation incl. zstd+gzip (Tasks 2–3, 9), namespace/cluster filtering via index (Task 5), informer feed + drop Redis (Tasks 10–12), pass-through for non-list incl. `?watch=true` (Task 11 `tryServeList` returns false → proxy). Global-version invalidation (Tasks 4, 8, 9). Covered.
- **Out of scope (unchanged):** JWT signature verification / RBAC fidelity / field projection — intentionally not in this plan, matching the spec.
- **Type consistency:** `encoding`, `compress`, `AppStore.{Version,Upsert,Delete,Items}`, `scopeKey`, `assembleItems`, `etag`, `cacheEntry.variant`, `ResponseCache.{Get,Put}`, `buildCacheEntry`, `serveApplicationList`, `tryServeList`, `appIDAndRaw`, `startApplicationInformer` are used with consistent signatures across tasks.
- **Note:** `compress`/`encoding` are common identifiers; if they collide with anything during implementation, prefix with `resp` (`respEncoding`, `respCompress`). No collision in the current single-package layout.
