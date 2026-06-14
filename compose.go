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
