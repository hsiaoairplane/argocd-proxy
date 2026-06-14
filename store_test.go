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
