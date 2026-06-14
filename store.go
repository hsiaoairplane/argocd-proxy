package main

import (
	"bytes"
	"encoding/json"
	"sort"
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
