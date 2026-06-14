package main

import "testing"

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
