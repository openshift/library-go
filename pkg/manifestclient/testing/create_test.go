package testing

import (
	"context"
	"net/http"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/openshift/library-go/pkg/manifestclient"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyconfigurationscorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestUpdateConfigMapLabel(t *testing.T) {
	client := setupKubernetesClient(t)
	configMap, err := client.CoreV1().ConfigMaps("openshift-authentication").Get(context.TODO(), "audit", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error updating configmap: %v", err)
	}
	updated := configMap.DeepCopy()
	updated.Labels = map[string]string{"mynew": "label"}
	_, err = client.CoreV1().ConfigMaps(updated.Namespace).Update(context.TODO(), updated, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to update configmap: %v", err)
	}
}

func TestRestClientContentType(t *testing.T) {

	testCases := []struct {
		desc               string
		client             *kubernetes.Clientset
		config             *v1.ConfigMap
		expectedRegexError *regexp.Regexp
	}{
		{
			desc:   "should succeed with RecommendedRESTConfig settings",
			client: setupCustomKubernetesClient(t, manifestclient.RecommendedRESTConfig()),
			config: &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-new-configmap",
					Namespace: "openshift-authentication",
				},
				Data: map[string]string{"config.txt": "super: cool config"},
			},
		},
		{
			desc:   "should succeed with RecommendedKubernetesWithClient client",
			client: setupKubernetesClient(t),
			config: &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-new-configmap-decoded",
					Namespace: "openshift-authentication",
				},
				Data: map[string]string{"config.txt": "super: cool config"},
			},
		},
		{
			desc:   "should fail with encoding error when no decoding",
			client: setupCustomKubernetesClient(t, &rest.Config{}),
			config: &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-new-configmap-decoded",
					Namespace: "openshift-authentication",
				},
				Data: map[string]string{"config.txt": "super: cool config"},
			},
			expectedRegexError: regexp.MustCompile(`incorrect Content-Type header, expected one of: .* but got: application/vnd.kubernetes.protobuf`),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := tc.client.CoreV1().ConfigMaps("openshift-authentication").Create(context.TODO(), tc.config, metav1.CreateOptions{})
			if err != nil && tc.expectedRegexError == nil {
				t.Fatalf("error creating configmap: %v", err)
			} else if tc.expectedRegexError != nil && (err == nil || !tc.expectedRegexError.MatchString(err.Error())) {
				t.Fatalf("expected error to contain %s but got %v", tc.expectedRegexError.String(), err)
			}
		})
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

func TestApplyConfigMap(t *testing.T) {
	client := setupKubernetesClient(t)
	dummyConfigMap := applyconfigurationscorev1.ConfigMap("my-new-configmap-apply", "openshift-authentication").WithData(map[string]string{"config.txt": "super: cool config"})
	_, err := client.CoreV1().ConfigMaps("openshift-authentication").Apply(context.TODO(), dummyConfigMap, metav1.ApplyOptions{})
	if err != nil {
		t.Fatalf("error applying configmap: %v", err)
	}
}

func setupKubernetesClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	client, err := manifestclient.RecommendedKubernetesWithClient(setupRoundTripperClient(t))
	if err != nil {
		t.Fatalf("failure creating kubernetes client with RecommendedKubernetesWithClient: %v", err)
	}
	return client
}

func setupRoundTripperClient(t *testing.T) *http.Client {
	roundTripper := manifestclient.NewRoundTripper(filepath.Join("test-data", "input-dir"))
	return &http.Client{
		Transport: roundTripper,
	}
}

func setupCustomKubernetesClient(t *testing.T, config *rest.Config) *kubernetes.Clientset {
	t.Helper()
	k8sClient, err := kubernetes.NewForConfigAndClient(config, setupRoundTripperClient(t))
	if err != nil {
		t.Fatalf("failure creating kubernetes client for NewForConfigAndClient: %v", err)
	}
	return k8sClient
}
