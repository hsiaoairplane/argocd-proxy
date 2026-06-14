package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestNegotiateEncoding(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   encoding
	}{
		{"zstd preferred", "gzip, deflate, zstd", encZstd},
		{"gzip when no zstd", "gzip, deflate", encGzip},
		{"identity when none", "deflate, br", encIdentity},
		{"empty header", "", encIdentity},
		{"zstd only", "zstd", encZstd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := negotiateEncoding(tt.header); got != tt.want {
				t.Errorf("negotiateEncoding(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

func TestCompressRoundTrip(t *testing.T) {
	payload := []byte(`{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`)

	gz := compress(encGzip, payload)
	if len(gz) == 0 {
		t.Fatal("gzip produced empty output")
	}
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, _ := io.ReadAll(gr)
	if !bytes.Equal(got, payload) {
		t.Errorf("gzip round-trip mismatch")
	}

	zs := compress(encZstd, payload)
	dec, _ := zstd.NewReader(nil)
	gotZ, err := dec.DecodeAll(zs, nil)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}
	if !bytes.Equal(gotZ, payload) {
		t.Errorf("zstd round-trip mismatch")
	}

	if id := compress(encIdentity, payload); !bytes.Equal(id, payload) {
		t.Errorf("identity must return input unchanged")
	}
}
