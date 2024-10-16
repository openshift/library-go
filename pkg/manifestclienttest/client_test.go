package manifestclienttest

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/manifestclient"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:embed testdata
var packageTestData embed.FS

func TestSimpleChecks(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(*testing.T, *http.Client)
	}{
		{
			name: "GET-from-individual-file-success",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				featureGatesCluster, err := configClient.ConfigV1().FeatureGates().Get(context.TODO(), "cluster", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(featureGatesCluster.Status.FeatureGates) == 0 {
					t.Fatal(spew.Sdump(featureGatesCluster))
				}
			},
		},
		{
			name: "GET-namespaced-list-file",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().Secrets("openshift-apiserver").Get(context.TODO(), "default-dockercfg-nrrk8", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if obj == nil {
					t.Fatal("missing")
				}
			},
		},
		{
			name: "GET-namespaced-individual-file",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().Secrets("openshift-apiserver").Get(context.TODO(), "pull-secret", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if obj == nil {
					t.Fatal("missing")
				}
			},
		},
		{
			name: "GET-missing",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				respObj, err := configClient.ConfigV1().FeatureGates().Get(context.TODO(), "missing", metav1.GetOptions{})
				if !apierrors.IsNotFound(err) {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(respObj, &configv1.FeatureGate{}) {
					t.Fatal(respObj)
				}
			},
		},
		{
			name: "LIST-from-cluster-scoped-list-file",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := configClient.ConfigV1().FeatureGates().List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) == 0 {
					t.Fatal(spew.Sdump(obj))
				}
			},
		},
		{
			name: "LIST-from-cluster-scoped-individual-files",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := apiextensionsclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := configClient.ApiextensionsV1().CustomResourceDefinitions().List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 2 {
					t.Fatal(len(obj.Items))
				}
			},
		},
		{
			name: "LIST-from-multiple-namespaced-scoped-list-files",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.AppsV1().Deployments("").List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 3 {
					t.Fatal(len(obj.Items))
				}
			},
		},
		{
			name: "LIST-namespace-scoped-prefer-list",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().Secrets("openshift-apiserver").List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 10 {
					t.Fatal(len(obj.Items))
				}
			},
		},
		{
			name: "LIST-namespace-scoped-secret-from-missing-namespace-with-list-file",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().Secrets("non-existent-namespace").List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 0 {
					t.Fatal(len(obj.Items))
				}
			},
		},
		{
			name: "LIST-namespace-scoped-configmap-from-missing-namespace-with-individual-file",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().ConfigMaps("non-existent-namespace").List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 0 {
					t.Fatal(len(obj.Items))
				}
			},
		},
		{
			name: "GET-namespace",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), "openshift-apiserver", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if obj.Labels["pod-security.kubernetes.io/audit"] != "privileged" {
					t.Fatal(obj)
				}
			},
		},
		{
			name: "LIST-namespace",
			testFn: func(t *testing.T, httpClient *http.Client) {
				kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := kubeClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 3 {
					t.Fatal(obj)
				}
			},
		},
	}

	for _, roundTripperTest := range defaultRoundTrippers(t) {
		t.Run(roundTripperTest.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					test.testFn(t, roundTripperTest.getClient().GetHTTPClient())
				})
			}
		})
	}
}

func defaultRoundTrippers(t *testing.T) []*testRoundTrippers {
	t.Helper()

	return []*testRoundTrippers{
		{
			name: "directory read",
			newClientFn: func() manifestclient.MutationTrackingClient {
				return manifestclient.NewHTTPClient("testdata/must-gather-01")
			},
		},
		{
			name: "embed read",
			newClientFn: func() manifestclient.MutationTrackingClient {
				embeddedReadFS, err := fs.Sub(packageTestData, "testdata/must-gather-01")
				if err != nil {
					t.Fatal(err)
				}
				return manifestclient.NewTestingHTTPClient(embeddedReadFS)
			},
		},
	}
}

type testRoundTrippers struct {
	name        string
	newClientFn func() manifestclient.MutationTrackingClient
}

func (r *testRoundTrippers) getClient() manifestclient.MutationTrackingClient {
	return r.newClientFn()
}

func TestWatchChecks(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(*testing.T, *http.Client)
	}{
		{
			name: "WATCH-from-individual-file-success-server-close",
			testFn: func(t *testing.T, httpClient *http.Client) {
				timeout := int64(4)
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				watcher, err := configClient.ConfigV1().FeatureGates().Watch(context.TODO(), metav1.ListOptions{
					TimeoutSeconds: &timeout,
				})
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-watcher.ResultChan():
					t.Fatal("closed early!")
				case <-time.After(500 * time.Millisecond):
				}

				select {
				case <-watcher.ResultChan():
				case <-time.After(5 * time.Second):
					t.Fatal("closed late!")
				}
			},
		},
	}
	for _, roundTripperTest := range defaultRoundTrippers(t) {
		t.Run(roundTripperTest.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					test.testFn(t, roundTripperTest.getClient().GetHTTPClient())
				})
			}
		})
	}
}
