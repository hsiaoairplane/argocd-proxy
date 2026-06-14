package main

import (
	"bytes"
	"encoding/json"
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
