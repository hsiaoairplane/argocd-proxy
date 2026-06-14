package main

import (
	"bytes"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func TestAppIDAndRaw(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "my-app"},
		"spec":     map[string]interface{}{"project": "p"},
	}}
	id, raw, ok := appIDAndRaw(u)
	if !ok || id != "my-app" || len(raw) == 0 {
		t.Fatalf("appIDAndRaw(u) = %q,%q,%v", id, raw, ok)
	}

	// managedFields must be stripped from the stored bytes.
	u2 := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":          "x",
			"managedFields": []interface{}{map[string]interface{}{"manager": "argocd"}},
		},
	}}
	_, raw2, _ := appIDAndRaw(u2)
	if bytes.Contains(raw2, []byte("managedFields")) {
		t.Error("managedFields not stripped")
	}

	// Tombstone unwrapping for deletes.
	tomb := cache.DeletedFinalStateUnknown{Key: "k", Obj: u}
	if _, _, ok := appIDAndRaw(tomb); !ok {
		t.Error("failed to unwrap DeletedFinalStateUnknown")
	}

	// Unknown object types report not-ok.
	if _, _, ok := appIDAndRaw("not-an-object"); ok {
		t.Error("expected not-ok for unexpected type")
	}
}
