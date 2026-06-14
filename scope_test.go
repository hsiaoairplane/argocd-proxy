package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestScopeKey(t *testing.T) {
	k1 := scopeKey(map[string]struct{}{"a": {}, "b": {}}, "", "")
	k2 := scopeKey(map[string]struct{}{"b": {}, "a": {}}, "", "")
	if k1 != k2 {
		t.Errorf("scopeKey not order-independent: %q vs %q", k1, k2)
	}
	if scopeKey(map[string]struct{}{"a": {}}, "c1", "") == scopeKey(map[string]struct{}{"a": {}}, "c2", "") {
		t.Error("different cluster produced same key")
	}
	if scopeKey(map[string]struct{}{"a": {}}, "", "n1") == scopeKey(map[string]struct{}{"a": {}}, "", "n2") {
		t.Error("different namespace produced same key")
	}
	if scopeKey(map[string]struct{}{"a,b": {}}, "", "") == scopeKey(map[string]struct{}{"a": {}, "b": {}}, "", "") {
		t.Error("delimiter collision between {'a,b'} and {'a','b'}")
	}
}

func TestAssembleItems(t *testing.T) {
	items := [][]byte{[]byte(`{"metadata":{"name":"a"}}`), []byte(`{"metadata":{"name":"b"}}`)}
	body := assembleItems(items)

	want := `{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`
	if string(body) != want {
		t.Errorf("assembleItems = %s, want %s", body, want)
	}
	var decoded struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Items) != 2 || !bytes.Equal(decoded.Items[0], items[0]) {
		t.Errorf("items not preserved verbatim")
	}
	if string(assembleItems(nil)) != `{"items":[]}` {
		t.Errorf("empty assemble = %s, want {\"items\":[]}", assembleItems(nil))
	}
}

func TestETagStability(t *testing.T) {
	a := etag([]byte(`{"items":[1]}`))
	if a != etag([]byte(`{"items":[1]}`)) {
		t.Error("etag not stable for identical input")
	}
	if a == etag([]byte(`{"items":[2]}`)) {
		t.Error("etag collided for different input")
	}
	if len(a) < 2 || a[0] != '"' || a[len(a)-1] != '"' {
		t.Errorf("etag must be a quoted string, got %s", a)
	}
}
