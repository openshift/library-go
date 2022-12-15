package templateprocessingclient

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/apitesting"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/dynamic/fake"

	templatev1 "github.com/openshift/api/template/v1"
)

func TestProcessToList(t *testing.T) {
	scheme, codecFactory := apitesting.SchemeForOrDie(templatev1.Install)
	dtp := NewDynamicTemplateProcessor(fake.NewSimpleDynamicClient(scheme))
	input := sampleTemplate(t, codecFactory)
	output, err := dtp.ProcessToList(input)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if len(output.Object) == 0 || len(output.Items) == 0 {
		t.Errorf("Unexpected empty output.Object or output.Items")
	}
	if input.Namespace != "test-namespace" {
		t.Errorf("Unexpected input namespace modification %s", input.Namespace)
	}
	if ns, _, _ := unstructured.NestedString(output.Object, "metadata", "namespace"); ns != "test-namespace" {
		t.Errorf("Unexpected output namespace %s", ns)
	}
	objs, _, _ := unstructured.NestedSlice(output.Object, "items")
	if len(objs) != 1 {
		t.Errorf("Unexpected objects %#v", objs)
	}
	if kind, _, _ := unstructured.NestedString(objs[0].(map[string]interface{}), "kind"); kind != "Service" {
		t.Errorf("Unexpected kind %s", objs)
	}
	if params, _, _ := unstructured.NestedSlice(output.Object, "parameters"); len(params) != 2 {
		t.Errorf("Unexpected parameters %s", params)
	}

}

func sampleTemplate(t *testing.T, codecFactory serializer.CodecFactory) *templatev1.Template {
	data := []byte(`{
		"kind":"Template",
		"apiVersion":"template.openshift.io/v1",
		"metadata": {
			"name": "test-template",
			"namespace": "test-namespace"
		},
		"objects": [
			{
				"kind": "Service", "apiVersion": "v1",
				"metadata": {"labels": {"key1": "v1", "key2": "v2"}}
			}
		],
		"parameters": [
			{
				"name": "KEY",
				"value": "key"
			},
			{
				"name": "VALUE",
				"value": "value"
			}
		]
	}`)
	var template templatev1.Template
	if err := runtime.DecodeInto(codecFactory.UniversalDecoder(), data, &template); err != nil {
		t.Errorf("Unexpected error creating a template: %v", err)
	}
	return &template
}
