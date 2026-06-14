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
