package main

import (
	"context"
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

// appIDAndRaw extracts the store id (application name) and the trimmed JSON
// bytes for an informer event object, unwrapping delete tombstones. It strips
// metadata.managedFields, mirroring what argocd-watcher stores.
func appIDAndRaw(obj interface{}) (string, []byte, bool) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		t, isTomb := obj.(cache.DeletedFinalStateUnknown)
		if !isTomb {
			return "", nil, false
		}
		if u, ok = t.Obj.(*unstructured.Unstructured); !ok {
			return "", nil, false
		}
	}
	u = u.DeepCopy()
	unstructured.RemoveNestedField(u.Object, "metadata", "managedFields")
	raw, err := json.Marshal(u.Object)
	if err != nil {
		return "", nil, false
	}
	return u.GetName(), raw, true
}

var applicationGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "applications",
}

// startApplicationInformer launches a dynamic informer that keeps store in sync
// with Application objects in namespace, and blocks until the cache is synced.
func startApplicationInformer(ctx context.Context, client dynamic.Interface, namespace string, resync time.Duration, store *AppStore) error {
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(client, resync, namespace, nil)
	informer := factory.ForResource(applicationGVR).Informer()

	upsert := func(obj interface{}) {
		if id, raw, ok := appIDAndRaw(obj); ok {
			store.Upsert(id, raw)
		}
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    upsert,
		UpdateFunc: func(_, newObj interface{}) { upsert(newObj) },
		DeleteFunc: func(obj interface{}) {
			if id, _, ok := appIDAndRaw(obj); ok {
				store.Delete(id)
			}
		},
	}); err != nil {
		return err
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return context.Canceled
	}
	log.Infoln("Application informer cache synced")
	return nil
}
