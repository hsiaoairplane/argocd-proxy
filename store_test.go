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

func TestAppStoreItems(t *testing.T) {
	s := NewAppStore()
	s.Upsert("a", rawApp("a", "proj-a", "https://c1", "ns-1"))
	s.Upsert("b", rawApp("b", "proj-a", "https://c2", "ns-2"))
	s.Upsert("c", rawApp("c", "proj-b", "https://c1", "ns-1"))

	count := func(patterns map[string]struct{}, cluster, ns string) int {
		return len(s.Items(patterns, cluster, ns))
	}

	if n := count(map[string]struct{}{"*": {}}, "", ""); n != 3 {
		t.Errorf("wildcard count = %d, want 3", n)
	}
	if n := count(map[string]struct{}{"proj-a": {}}, "", ""); n != 2 {
		t.Errorf("proj-a count = %d, want 2", n)
	}
	if n := count(map[string]struct{}{"proj-a": {}}, "", "ns-1"); n != 1 {
		t.Errorf("proj-a/ns-1 count = %d, want 1", n)
	}
	if n := count(map[string]struct{}{"*": {}}, "https://c1", ""); n != 2 {
		t.Errorf("cluster c1 count = %d, want 2", n)
	}
	if n := count(map[string]struct{}{"proj-x": {}}, "", ""); n != 0 {
		t.Errorf("proj-x count = %d, want 0", n)
	}
}
