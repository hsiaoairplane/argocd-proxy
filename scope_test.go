package main

import "testing"

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
