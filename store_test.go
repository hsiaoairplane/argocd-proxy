package main

import (
	"reflect"
	"sort"
	"testing"
)

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
