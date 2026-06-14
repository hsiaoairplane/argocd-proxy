package main

import (
	"bytes"
	"compress/gzip"
	"strings"

	"github.com/klauspost/compress/zstd"
)

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

// zstdEncoder is safe for concurrent use via EncodeAll.
var zstdEncoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))

// compress returns data encoded with enc. encIdentity returns data unchanged.
func compress(enc encoding, data []byte) []byte {
	switch enc {
	case encZstd:
		return zstdEncoder.EncodeAll(data, make([]byte, 0, len(data)/3))
	case encGzip:
		var buf bytes.Buffer
		gw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		_, _ = gw.Write(data)
		_ = gw.Close()
		return buf.Bytes()
	default:
		return data
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
