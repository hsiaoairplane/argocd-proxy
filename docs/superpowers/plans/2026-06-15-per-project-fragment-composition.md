# Per-project fragment composition — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Serve every unfiltered list scope (team / admin / view-all) by concatenating per-project, pre-compressed item fragments — so a request does no per-request scan, assembly, or compression, and only the projects that actually changed get rebuilt.

**Architecture:** The `AppStore` gains a per-project index and per-project version counters. A `FragmentCache` holds, per project, the apps joined by comma (no envelope) pre-compressed in gzip+zstd, rebuilt lazily when that project's version changes. An unfiltered request resolves the caller's allowed projects from RBAC patterns and streams `{"items":[` + fragments joined by precompressed commas + `]}` — independently-compressed gzip members / zstd frames concatenate into a valid stream (verified). Filtered (cluster/namespace) queries still compute on demand (small results). ETags derive from per-project versions, so `If-None-Match` yields 304 unless an in-scope project changed.

**Tech Stack:** Go, `github.com/klauspost/compress/zstd`, stdlib `compress/gzip`, `net/http`.

**Base branch:** `feat/fast-list-proxy` (PR #77). This plan replaces the per-scope `ResponseCache` with the per-project `FragmentCache`.

**Spec reference:** the design discussion in this PR; key property verified — concatenated independent gzip members and zstd frames decompress to the concatenation of their inputs.

---

## File structure

- Modify `store.go` — add `byProject` index + `projectVersion`; new methods `ProjectNames`, `ProjectVersion`, `ProjectItems`. Keep `Items` (used by the filtered path).
- Modify `compress.go` — precompressed envelope constants (`{"items":[`, `,`, `]}`) per encoding.
- Replace `cache.go` — `FragmentCache` + `fragment` (per project) instead of `ResponseCache` + `cacheEntry`.
- Create `compose.go` — `resolveProjects`, `composeETag`, `writeComposedList`.
- Modify `listhandler.go` — `serveApplicationList` dispatches to `serveComposed` (unfiltered) or `serveFiltered` (cluster/namespace); `tryServeList` takes `*FragmentCache`.
- Modify `scope.go` — remove now-unused `scopeKey`; keep `assembleItems` + `etag` (filtered path).
- Modify `main.go` — construct `NewFragmentCache`; remove dead `ResponseCache` references.

---

## Task 1: AppStore per-project index + versions

**Files:** Modify `store.go`, `store_test.go`

- [ ] **Step 1: Write the failing test (append to store_test.go)**

```go
func TestAppStoreProjectIndex(t *testing.T) {
	s := NewAppStore()
	s.Upsert("a", rawApp("a", "p1", "https://c1", "ns-1"))
	s.Upsert("b", rawApp("b", "p1", "https://c1", "ns-2"))
	s.Upsert("c", rawApp("c", "p2", "https://c1", "ns-1"))

	names := s.ProjectNames()
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"p1", "p2"}) {
		t.Errorf("ProjectNames = %v, want [p1 p2]", names)
	}
	if n := len(s.ProjectItems("p1")); n != 2 {
		t.Errorf("ProjectItems(p1) = %d, want 2", n)
	}

	v1 := s.ProjectVersion("p1")
	// No-op upsert: version unchanged.
	s.Upsert("a", rawApp("a", "p1", "https://c1", "ns-1"))
	if s.ProjectVersion("p1") != v1 {
		t.Errorf("no-op upsert bumped p1 version")
	}
	// Change an app in p1: only p1 version bumps.
	v2before := s.ProjectVersion("p2")
	s.Upsert("a", rawApp("a", "p1", "https://c1", "ns-9"))
	if s.ProjectVersion("p1") != v1+1 {
		t.Errorf("changed app did not bump p1 version")
	}
	if s.ProjectVersion("p2") != v2before {
		t.Errorf("p2 version changed when only p1 changed")
	}

	// Move app c from p2 to p1: both versions bump, indexes updated.
	p1v := s.ProjectVersion("p1")
	p2v := s.ProjectVersion("p2")
	s.Upsert("c", rawApp("c", "p1", "https://c1", "ns-1"))
	if s.ProjectVersion("p1") <= p1v || s.ProjectVersion("p2") <= p2v {
		t.Errorf("project move did not bump both versions")
	}
	if len(s.ProjectItems("p1")) != 3 || len(s.ProjectItems("p2")) != 0 {
		t.Errorf("project move did not update indexes: p1=%d p2=%d",
			len(s.ProjectItems("p1")), len(s.ProjectItems("p2")))
	}
	if names := s.ProjectNames(); contains(names, "p2") {
		t.Errorf("empty project p2 still listed in ProjectNames: %v", names)
	}

	// Delete bumps the project version and drops the app.
	dv := s.ProjectVersion("p1")
	s.Delete("a")
	if s.ProjectVersion("p1") <= dv {
		t.Errorf("delete did not bump project version")
	}
	if len(s.ProjectItems("p1")) != 2 {
		t.Errorf("delete did not update index")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
```

Add `"reflect"` to store_test.go imports if missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestAppStoreProjectIndex`
Expected: FAIL — `ProjectNames`/`ProjectVersion`/`ProjectItems` undefined.

- [ ] **Step 3: Implement (modify store.go)**

Replace the `AppStore` struct, `NewAppStore`, `Upsert`, and `Delete` with:

```go
type AppStore struct {
	mu             sync.RWMutex
	apps           map[string]appEntry
	byProject      map[string]map[string]struct{} // project -> set of ids
	projectVersion map[string]uint64
	version        uint64
}

func NewAppStore() *AppStore {
	return &AppStore{
		apps:           make(map[string]appEntry),
		byProject:      make(map[string]map[string]struct{}),
		projectVersion: make(map[string]uint64),
	}
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
	if old, ok := s.apps[id]; ok {
		if bytes.Equal(old.raw, entry.raw) {
			return
		}
		if old.project != entry.project {
			s.removeFromProjectLocked(id, old.project)
		}
	}
	s.apps[id] = entry
	ids := s.byProject[entry.project]
	if ids == nil {
		ids = make(map[string]struct{})
		s.byProject[entry.project] = ids
	}
	ids[id] = struct{}{}
	s.projectVersion[entry.project]++
	s.version++
}

func (s *AppStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.apps[id]
	if !ok {
		return
	}
	delete(s.apps, id)
	s.removeFromProjectLocked(id, e.project)
	s.version++
}

// removeFromProjectLocked drops id from a project's index and bumps that
// project's version. Caller must hold s.mu.
func (s *AppStore) removeFromProjectLocked(id, project string) {
	ids := s.byProject[project]
	if ids == nil {
		return
	}
	delete(ids, id)
	if len(ids) == 0 {
		delete(s.byProject, project)
	}
	s.projectVersion[project]++
}
```

Then add the accessors (anywhere in store.go):

```go
// ProjectNames returns the names of all projects that currently have at least
// one application. The caller may sort the result.
func (s *AppStore) ProjectNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.byProject))
	for p := range s.byProject {
		names = append(names, p)
	}
	return names
}

// ProjectVersion returns the version counter for a project, which increments
// whenever that project's set of applications changes.
func (s *AppStore) ProjectVersion(project string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.projectVersion[project]
}

// ProjectItems returns the raw JSON of every application in a project, sorted by
// id for deterministic output.
func (s *AppStore) ProjectItems(project string) [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idset := s.byProject[project]
	ids := make([]string, 0, len(idset))
	for id := range idset {
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

Keep the existing `Items` method and `parseAppEntry` unchanged.

- [ ] **Step 4: Run tests**

Run: `go test ./... -run 'TestAppStore'`
Expected: PASS (TestAppStoreProjectIndex, TestAppStoreUpsertDeleteVersion, TestAppStoreItems).

- [ ] **Step 5: Commit**

```bash
git add store.go store_test.go
git commit -m "feat: add per-project index and version counters to AppStore"
```

---

## Task 2: Precompressed envelope constants

**Files:** Modify `compress.go`, `compress_test.go`

- [ ] **Step 1: Write the failing test (append to compress_test.go)**

```go
func TestCompressedConsts(t *testing.T) {
	for _, enc := range []encoding{encIdentity, encGzip, encZstd} {
		c := compressedConsts[enc]
		if c.open == nil || c.comma == nil || c.close == nil {
			t.Fatalf("enc %v: missing precompressed constants", enc)
		}
		// Concatenated pieces must decompress to the raw envelope fragments.
		stream := append(append(append([]byte{}, c.open...), c.comma...), c.close...)
		got := decodeForTest(t, enc, stream)
		if string(got) != `{"items":[`+`,`+`]}` {
			t.Errorf("enc %v: decoded %q", enc, got)
		}
	}
}
```

Add a small test decode helper to compress_test.go (and imports `bytes`, `compress/gzip`, `io`, `github.com/klauspost/compress/zstd` if not already present):

```go
func decodeForTest(t *testing.T, enc encoding, b []byte) []byte {
	t.Helper()
	switch enc {
	case encGzip:
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		out, _ := io.ReadAll(r)
		return out
	case encZstd:
		d, _ := zstd.NewReader(nil)
		out, err := d.DecodeAll(b, nil)
		if err != nil {
			t.Fatalf("zstd: %v", err)
		}
		return out
	default:
		return b
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestCompressedConsts`
Expected: FAIL — `compressedConsts` undefined.

- [ ] **Step 3: Implement (append to compress.go)**

```go
var (
	openItemsBytes  = []byte(`{"items":[`)
	commaBytes      = []byte(`,`)
	closeItemsBytes = []byte(`]}`)
)

// constPieces holds the precompressed envelope fragments for one encoding.
type constPieces struct {
	open  []byte
	comma []byte
	close []byte
}

// compressedConsts holds, per encoding, the precompressed {"items":[ , and ]}
// pieces, so composed responses never recompress these constants.
var compressedConsts map[encoding]constPieces

func init() {
	compressedConsts = map[encoding]constPieces{
		encIdentity: {open: openItemsBytes, comma: commaBytes, close: closeItemsBytes},
		encGzip: {
			open:  compress(encGzip, openItemsBytes),
			comma: compress(encGzip, commaBytes),
			close: compress(encGzip, closeItemsBytes),
		},
		encZstd: {
			open:  compress(encZstd, openItemsBytes),
			comma: compress(encZstd, commaBytes),
			close: compress(encZstd, closeItemsBytes),
		},
	}
}
```

- [ ] **Step 4: Run test**

Run: `go test ./... -run TestCompressedConsts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add compress.go compress_test.go
git commit -m "feat: add precompressed envelope constants"
```

---

## Task 3: FragmentCache (per-project fragments)

**Files:** Replace `cache.go`; replace `cache_test.go`

- [ ] **Step 1: Replace cache_test.go with**

```go
package main

import (
	"bytes"
	"testing"
)

func TestFragmentCache(t *testing.T) {
	store := NewAppStore()
	store.Upsert("a", rawApp("a", "p1", "https://c1", "ns-1"))
	store.Upsert("b", rawApp("b", "p1", "https://c1", "ns-2"))
	fc := NewFragmentCache()

	f1 := fc.Fragment(store, "p1")
	// raw is the apps joined by comma with no envelope.
	if !bytes.HasPrefix(f1.raw, []byte(`{`)) || bytes.Contains(f1.raw, []byte(`"items"`)) {
		t.Errorf("fragment raw should be bare apps joined by comma, got %s", f1.raw)
	}
	if !bytes.Equal(f1.variant(encGzip), compress(encGzip, f1.raw)) {
		t.Errorf("gzip variant mismatch")
	}

	// Same version -> same cached pointer.
	if f2 := fc.Fragment(store, "p1"); f2 != f1 {
		t.Errorf("expected cached fragment reuse at same version")
	}

	// Changing the project rebuilds the fragment.
	store.Upsert("a", rawApp("a", "p1", "https://c1", "ns-9"))
	if f3 := fc.Fragment(store, "p1"); f3 == f1 {
		t.Errorf("expected fragment rebuild after project change")
	}

	// Empty project -> empty raw fragment.
	if fe := fc.Fragment(store, "does-not-exist"); len(fe.raw) != 0 {
		t.Errorf("empty project fragment should be empty, got %s", fe.raw)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestFragmentCache`
Expected: FAIL — `NewFragmentCache` undefined (and the file still defines the old ResponseCache; that's fine, it will be removed in this step's implementation).

- [ ] **Step 3: Replace the entire contents of cache.go with**

```go
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
```

- [ ] **Step 4: Run test**

Run: `go test ./... -run TestFragmentCache`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cache.go cache_test.go
git commit -m "feat: replace per-scope cache with per-project FragmentCache"
```

Note: `go build ./...` will now fail elsewhere because `main.go`/`listhandler.go` still reference the removed `ResponseCache`/`buildCacheEntry`. That is expected and fixed in Tasks 5–6.

---

## Task 4: Composition (resolve projects, ETag, stream)

**Files:** Create `compose.go`, `compose_test.go`

- [ ] **Step 1: Write the failing test compose_test.go**

```go
package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
)

func TestResolveProjects(t *testing.T) {
	store := NewAppStore()
	store.Upsert("a", rawApp("a", "p1", "https://c", "ns"))
	store.Upsert("b", rawApp("b", "p2", "https://c", "ns"))

	all := resolveProjects(map[string]struct{}{"*": {}}, store)
	sort.Strings(all)
	if len(all) != 2 || all[0] != "p1" || all[1] != "p2" {
		t.Errorf("wildcard resolveProjects = %v, want [p1 p2]", all)
	}
	one := resolveProjects(map[string]struct{}{"p1": {}}, store)
	if len(one) != 1 || one[0] != "p1" {
		t.Errorf("named resolveProjects = %v, want [p1]", one)
	}
}

func TestWriteComposedListDecodes(t *testing.T) {
	store := NewAppStore()
	store.Upsert("a", rawApp("a", "p1", "https://c", "ns-1"))
	store.Upsert("b", rawApp("b", "p1", "https://c", "ns-2"))
	store.Upsert("c", rawApp("c", "p2", "https://c", "ns-3"))
	store.Upsert("e", rawApp("e", "empty-after", "https://c", "ns")) // will be removed
	store.Delete("e")                                                // leaves an empty project name out of the index
	fc := NewFragmentCache()

	projects := resolveProjects(map[string]struct{}{"*": {}}, store)
	sort.Strings(projects)

	for _, enc := range []encoding{encIdentity, encGzip, encZstd} {
		var buf bytes.Buffer
		writeComposedList(&buf, enc, store, fc, projects)
		body := decodeForTest(t, enc, buf.Bytes())

		var decoded struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("enc %v: composed body is not valid JSON: %v\nbody=%s", enc, err, body)
		}
		if len(decoded.Items) != 3 {
			t.Errorf("enc %v: got %d items, want 3", enc, len(decoded.Items))
		}
	}
}

func TestComposeETag(t *testing.T) {
	store := NewAppStore()
	store.Upsert("a", rawApp("a", "p1", "https://c", "ns-1"))
	projects := []string{"p1"}

	e1 := composeETag(store, projects)
	if composeETag(store, projects) != e1 {
		t.Error("composeETag not stable for unchanged store")
	}
	store.Upsert("a", rawApp("a", "p1", "https://c", "ns-2")) // change p1
	if composeETag(store, projects) == e1 {
		t.Error("composeETag did not change after project change")
	}
	if len(e1) < 2 || e1[0] != '"' {
		t.Errorf("composeETag must be a quoted string, got %s", e1)
	}
}
```

This test reuses `decodeForTest` from compress_test.go (same package).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestResolveProjects|TestWriteComposedListDecodes|TestComposeETag'`
Expected: FAIL — undefined `resolveProjects`/`writeComposedList`/`composeETag`.

- [ ] **Step 3: Implement compose.go**

```go
package main

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strconv"
)

// resolveProjects returns the sorted set of projects the patterns grant. "*"
// expands to every project currently in the store.
func resolveProjects(patterns map[string]struct{}, store *AppStore) []string {
	if _, all := patterns["*"]; all {
		names := store.ProjectNames()
		sort.Strings(names)
		return names
	}
	names := make([]string, 0, len(patterns))
	for p := range patterns {
		names = append(names, p)
	}
	sort.Strings(names)
	return names
}

// composeETag derives a strong, quoted ETag from each in-scope project's
// version, so it changes iff an in-scope project's content changes.
func composeETag(store *AppStore, projects []string) string {
	h := fnv.New64a()
	for _, p := range projects {
		fmt.Fprintf(h, "%s:%d;", p, store.ProjectVersion(p))
	}
	return `"` + strconv.FormatUint(h.Sum64(), 16) + `"`
}

// writeComposedList streams {"items":[...]} for the given projects by
// concatenating each project's precompressed fragment with precompressed
// separators — no per-request assembly or compression.
func writeComposedList(w io.Writer, enc encoding, store *AppStore, fc *FragmentCache, projects []string) {
	c := compressedConsts[enc]
	bw := bufio.NewWriter(w)
	bw.Write(c.open)
	first := true
	for _, p := range projects {
		f := fc.Fragment(store, p)
		if len(f.raw) == 0 {
			continue
		}
		if !first {
			bw.Write(c.comma)
		}
		bw.Write(f.variant(enc))
		first = false
	}
	bw.Write(c.close)
	_ = bw.Flush()
}
```

- [ ] **Step 4: Run test**

Run: `go test ./... -run 'TestResolveProjects|TestWriteComposedListDecodes|TestComposeETag'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add compose.go compose_test.go
git commit -m "feat: add project resolution, composed ETag, and composed streaming"
```

---

## Task 5: Rewrite the list handler

**Files:** Modify `listhandler.go`, `listhandler_test.go`, `scope.go`

- [ ] **Step 1: Replace listhandler_test.go with**

```go
package main

import (
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
```

Add this tiny JSON helper to listhandler_test.go (keeps the appCount helper independent of import churn):

```go
import "encoding/json"

func jsonUnmarshalForTest(b []byte, v any) error { return json.Unmarshal(b, v) }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestServeApplicationList'`
Expected: FAIL to compile — `serveApplicationList` still has the old `*ResponseCache` signature.

- [ ] **Step 3: Replace the contents of listhandler.go with**

```go
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
```

- [ ] **Step 4: Remove the now-unused `scopeKey` from scope.go**

Delete the `scopeKey` function from `scope.go` and remove `strconv` from its imports **only if** `strconv` is otherwise unused there (`etag` uses `strconv.FormatUint`, so keep `strconv`). Keep `assembleItems` and `etag`. Run `go build ./...` to confirm whether `sort` is still used in scope.go (it is used by `scopeKey` only — if `scopeKey` was its only user, drop `sort` from scope.go's imports).

- [ ] **Step 5: Run tests**

Run: `go test ./... -run 'TestServeApplicationList'`
Expected: PASS (note: the package may not fully build until Task 6 wires main.go; if `go test` fails only due to main.go references to `ResponseCache`, proceed to Task 6, then re-run).

- [ ] **Step 6: Commit**

```bash
git add listhandler.go listhandler_test.go scope.go
git commit -m "feat: serve unfiltered scopes via per-project fragment composition"
```

---

## Task 6: Wire main.go and remove dead code

**Files:** Modify `main.go`

- [ ] **Step 1: Swap the cache type in main()**

In `main.go`, replace `cacheStore := NewResponseCache()` with:

```go
fragCache := NewFragmentCache()
```

and update the mux handler call from `tryServeList(rw, r, store, cacheStore, ...)` to:

```go
tryServeList(rw, r, store, fragCache, userToObjectPatternMapping, groupToObjectPatternMapping)
```

- [ ] **Step 2: Build and fix references**

Run: `go build ./...`
Expected: success. If it reports unused/undefined symbols, ensure no remaining references to `ResponseCache`, `cacheEntry`, `buildCacheEntry`, or `scopeKey` exist anywhere.

- [ ] **Step 3: Run the full suite (with race)**

Run: `go vet ./... && go test -race ./... && gofmt -l .`
Expected: vet clean, tests PASS, gofmt lists no files.

- [ ] **Step 4: Commit**

```bash
git add main.go
git commit -m "feat: wire FragmentCache into main, remove per-scope cache"
```

---

## Task 7: Integration test — composed stream is decodable and complete

**Files:** Create `compose_integration_test.go`

- [ ] **Step 1: Write the test**

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"sort"
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
	_ = sort.Strings
}
```

- [ ] **Step 2: Run test**

Run: `go test ./... -run TestComposedAdminCompleteness`
Expected: PASS.

- [ ] **Step 3: Final verification**

Run: `go build ./... && go vet ./... && go test -race ./... && gofmt -l .`
Expected: all clean.

- [ ] **Step 4: Commit**

```bash
git add compose_integration_test.go
git commit -m "test: composed admin/scoped responses decode to the full set"
```

---

## Self-review notes

- **Spec coverage:** per-project index + versions (Task 1); precompressed envelope constants enabling no-recompress composition (Task 2); per-project fragment cache rebuilt lazily on project change (Task 3); project resolution + version-derived ETag + concatenated streaming (Task 4); handler dispatch composed-vs-filtered, 304, empty-filter→{"items":[]} (Task 5); wiring + dead-code removal (Task 6); end-to-end completeness across encodings (Task 7).
- **Concatenation correctness:** verified out-of-band that concatenated independent gzip members and zstd frames decompress to the concatenation; Tasks 4 and 7 assert it via `decodeForTest`.
- **Behavior change:** the unfiltered empty-scope fall-through now only triggers when there are zero in-scope projects (e.g. empty store under "*"); a named scope with apps always serves. Filtered empty results return 200 `{"items":[]}` (preserved from the prior fix).
- **Type consistency:** `FragmentCache.Fragment`, `fragment.variant`, `joinItems`, `resolveProjects`, `composeETag`, `writeComposedList`, `compressedConsts`/`constPieces`, `AppStore.{ProjectNames,ProjectVersion,ProjectItems}` are referenced consistently across tasks. `decodeForTest`/`appCount`/`jsonUnmarshalForTest` are shared test helpers in package `main`.
- **Out of scope (unchanged):** JWT signature verification / RBAC fidelity (still exact project match + `*`); pagination (`offset`/`limit`) — not implemented here; filtered queries still use the O(total) `Items` scan (fast enough at measured scale).
