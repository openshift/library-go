package resourceapply

import (
	"fmt"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestHashOfResourceStructUnstructured(t *testing.T) {
	unstructuredObject := unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind":       "Service",
			"apiVersion": "v1",
			"metadata": map[string]interface{}{
				"name":      "svc1",
				"namespace": "ns1",
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"foo": "bar",
				},
				"ports": []map[string]interface{}{
					{
						"protocol":   "TCP",
						"port":       80,
						"targetPort": 9376,
					},
				},
			},
		},
	}
	hash := hashOfResourceStruct(&unstructuredObject)
	unstructuredObject.Object["spec"].(map[string]interface{})["selector"].(map[string]interface{})["foo"] = "baz"
	if hashOfResourceStruct(&unstructuredObject) == hash {
		t.Errorf("expected a different hash after modifying the object")
	}
}

// This test relies on -race to deterministically detect concurrent map access.
// See https://github.com/openshift/library-go/pull/2380.
func TestResourceCacheConcurrentAccess(t *testing.T) {
	cache := NewResourceCache()

	makeObj := func(i int, rv string) *unstructured.Unstructured {
		return &unstructured.Unstructured{
			Object: map[string]interface{}{
				"kind":       "ConfigMap",
				"apiVersion": "v1",
				"metadata": map[string]interface{}{
					"name":            fmt.Sprintf("obj-%d", i),
					"namespace":       "test-ns",
					"resourceVersion": rv,
				},
			},
		}
	}

	var wg sync.WaitGroup

	for range 10 {
		wg.Go(func() {
			for i := range 10 {
				cache.UpdateCachedResourceMetadata(makeObj(i, ""), makeObj(i, "1"))
			}
		})
	}

	for range 10 {
		wg.Go(func() {
			for i := range 10 {
				cache.SafeToSkipApply(makeObj(i, ""), makeObj(i, "1"))
			}
		})
	}

	wg.Wait()
}
