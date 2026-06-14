package main

import (
	"hash/fnv"
	"strconv"
	"strings"
)

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
