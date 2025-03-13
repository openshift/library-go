package testing

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/openshift/library-go/pkg/manifestclient"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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

func TestUpdateConfigMapLabel(t *testing.T) {
	client := setupKubernetesClient(t)
	configMapList, err := client.CoreV1().ConfigMaps("openshift-authentication").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("error updating configmap: %v", err)
	}

	var errList []error
	for _, configMap := range configMapList.Items {
		updated := configMap.DeepCopy()
		updated.Labels = map[string]string{"mynew": "label"}

		_, err := client.CoreV1().ConfigMaps("openshift-authentication").Update(context.TODO(), updated, metav1.UpdateOptions{})
		if err != nil {
			errList = append(errList, fmt.Errorf("failed to update %s/%s :%w", updated.Namespace, updated.Name, err))
		}
	}
	if errList != nil {
		t.Fatalf("failed to update some configmaps: %v", errors.NewAggregate(errList))
	}
}

func TestCreateConfigMap(t *testing.T) {
	client := setupKubernetesClient(t)

	dummyConfigMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-new-configmap",
			Namespace: "openshift-authentication",
		},
		Data: map[string]string{"config.txt": "super: cool config"},
	}

	_, err := client.CoreV1().ConfigMaps("openshift-authentication").Create(context.TODO(), dummyConfigMap, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating configmap: %v", err)
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

func setupKubernetesClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()

	roundTripper := manifestclient.NewRoundTripper(filepath.Join("test-data", "input-dir"))
	httpClient := &http.Client{
		Transport: roundTripper,
	}

	k8sClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
	if err != nil {
		t.Fatalf("failure creating dynamicClient for NewDynamicClientFromMustGather: %v", err)
	}

	return k8sClient
}
