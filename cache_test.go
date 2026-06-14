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
