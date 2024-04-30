package manifestclienttest

import (
	"context"
	"embed"
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
var mustGather01 embed.FS

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
				obj, err := kubeClient.CoreV1().Secrets("openshift-config").Get(context.TODO(), "deployer-dockercfg-7xzx7", metav1.GetOptions{})
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
				obj, err := kubeClient.CoreV1().Secrets("openshift-config").Get(context.TODO(), "pull-secret", metav1.GetOptions{})
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
				if len(obj.Items) != 120 {
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
				obj, err := kubeClient.AppsV1().DaemonSets("").List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 16 {
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
				obj, err := kubeClient.CoreV1().Secrets("openshift-config").List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(obj.Items) != 13 {
					t.Fatal(len(obj.Items))
				}
			},
		},
	}

	for _, roundTripperTest := range defaultRoundTrippers(t) {
		t.Run(roundTripperTest.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					test.testFn(t, roundTripperTest.getClient())
				})
			}
		})
	}
}

func defaultRoundTrippers(t *testing.T) []*testRoundTrippers {
	t.Helper()

	mustGatherRoundTripper, err := manifestclient.NewRoundTripper("testdata/must-gather-01")
	if err != nil {
		t.Fatal(err)
	}
	testRoundTripper, err := manifestclient.NewTestingRoundTripper(mustGather01, "testdata/must-gather-01")
	if err != nil {
		t.Fatal(err)
	}

	return []*testRoundTrippers{
		{
			name:         "directory read",
			roundTripper: mustGatherRoundTripper,
		},
		{
			name:         "embed read",
			roundTripper: testRoundTripper,
		},
	}
}

type testRoundTrippers struct {
	name         string
	roundTripper http.RoundTripper
}

func (r *testRoundTrippers) getClient() *http.Client {
	return &http.Client{
		Transport: r.roundTripper,
	}
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
					test.testFn(t, roundTripperTest.getClient())
				})
			}
		})
	}
}
