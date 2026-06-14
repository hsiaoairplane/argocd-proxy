package main

import (
	"hash/fnv"
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
