package main

import "strings"

type encoding int

const (
	encIdentity encoding = iota
	encGzip
	encZstd
)

func (e encoding) header() string {
	switch e {
	case encZstd:
		return "zstd"
	case encGzip:
		return "gzip"
	default:
		return ""
	}
}

// negotiateEncoding picks the best response encoding the client accepts,
// preferring zstd, then gzip, then identity. Quality values are ignored; a
// token is treated as accepted if it appears at all.
func negotiateEncoding(acceptEncoding string) encoding {
	tokens := make(map[string]bool)
	for _, part := range strings.Split(acceptEncoding, ",") {
		name := strings.TrimSpace(part)
		if i := strings.IndexByte(name, ';'); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		if name != "" {
			tokens[strings.ToLower(name)] = true
		}
	}
	switch {
	case tokens["zstd"]:
		return encZstd
	case tokens["gzip"]:
		return encGzip
	default:
		return encIdentity
	}
}
