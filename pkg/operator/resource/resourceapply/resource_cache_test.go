package resourceapply

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
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
