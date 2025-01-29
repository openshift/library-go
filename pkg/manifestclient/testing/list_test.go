package testing

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/openshift/library-go/pkg/manifestclient"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// This test also makes sure that the AuthorizeWithSelectors feature gate is properly set in the manifestclient package.
func TestListWithLabelSelector_FindsExpectedConfigMaps(t *testing.T) {
	gvr := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "configmaps",
	}
	dynamicClient := setupDynamicClient(t)

	labelSelector := "operator.openshift.io/controller-instance-name=oauth-apiserver-RevisionController"
	unstructuredList, err := dynamicClient.Resource(gvr).Namespace("openshift-authentication").List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		t.Fatalf("fail to list resources with labelSelector %s: %v", labelSelector, err)
	}

	expectedConfigMaps := map[string]bool{
		"revision-status-1": false,
		"audit-1":           false,
	}
	for _, obj := range unstructuredList.Items {
		castObj := &v1.ConfigMap{}
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj)
		if err != nil {
			t.Fatalf("unable to convert to configMap: %v", err)
		}
		if _, ok := expectedConfigMaps[castObj.Name]; ok {
			expectedConfigMaps[castObj.Name] = true
		} else {
			t.Errorf("unexpected configMap %s was listed", castObj.Name)
		}
	}

	for k, v := range expectedConfigMaps {
		if !v {
			t.Errorf("expected configMap %s, got nothing", k)
		}
	}
}

func setupDynamicClient(t *testing.T) dynamic.Interface {
	t.Helper()

	roundTripper := manifestclient.NewRoundTripper(filepath.Join("test-data", "input-dir"))
	httpClient := &http.Client{
		Transport: roundTripper,
	}

	dynamicClient, err := dynamic.NewForConfigAndClient(&rest.Config{}, httpClient)
	if err != nil {
		t.Fatalf("failure creating dynamicClient for NewDynamicClientFromMustGather: %v", err)
	}

	return dynamicClient
}
