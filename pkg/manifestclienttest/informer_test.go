package manifestclienttest

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func TestBasicInformer(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(*testing.T, *http.Client)
	}{
		{
			name: "informer-synced-compiled-client-with-data",
			testFn: func(t *testing.T, httpClient *http.Client) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				informers := configinformers.NewSharedInformerFactory(configClient, 0)
				featureGateInformer := informers.Config().V1().FeatureGates()
				featureGateInformer.Informer()
				informers.Start(ctx.Done())

				timedOutCh := make(chan struct{})
				go func() {
					select {
					case <-time.After(1 * time.Second):
						close(timedOutCh)
					}
				}()
				if !cache.WaitForCacheSync(timedOutCh, featureGateInformer.Informer().HasSynced) {
					t.Fatal("failed to sync")
				}

				featureGatesCluster, err := featureGateInformer.Lister().Get("cluster")
				if err != nil {
					t.Fatal(err)
				}
				if len(featureGatesCluster.Status.FeatureGates) == 0 {
					t.Fatal(spew.Sdump(featureGatesCluster))
				}
				missing, err := featureGateInformer.Lister().Get("missing")
				if !apierrors.IsNotFound(err) {
					t.Fatal(err)
				}
				if missing != nil {
					t.Fatal(missing)
				}
			},
		},
		{
			name: "informer-synced-compiled-client-not-in-must-gather",
			testFn: func(t *testing.T, httpClient *http.Client) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				informers := configinformers.NewSharedInformerFactory(configClient, 0)
				clusterOperatorInformer := informers.Config().V1().ClusterOperators()
				clusterOperatorInformer.Informer()
				informers.Start(ctx.Done())

				timedOutCh := make(chan struct{})
				go func() {
					select {
					case <-time.After(1 * time.Second):
						close(timedOutCh)
					}
				}()
				if !cache.WaitForCacheSync(timedOutCh, clusterOperatorInformer.Informer().HasSynced) {
					t.Fatal("failed to sync")
				}
			},
		},
		{
			// this usecase is critical because we need informers for namespaces that don't exist to indicate HasSynced
			// so that we can the namespace informerFactory HasSynced will report success and the RunOnce functions can run.
			name: "informer-synced-on-non-existent-namespace",
			testFn: func(t *testing.T, httpClient *http.Client) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				configClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				informers := kubeinformers.NewSharedInformerFactoryWithOptions(configClient, 0, kubeinformers.WithNamespace("not-present"))
				namespacedConfigInformer := informers.Core().V1().ConfigMaps()
				namespacedConfigInformer.Informer()
				informers.Start(ctx.Done())

				timedOutCh := make(chan struct{})
				go func() {
					select {
					case <-time.After(1 * time.Second):
						close(timedOutCh)
					}
				}()
				if !cache.WaitForCacheSync(timedOutCh, namespacedConfigInformer.Informer().HasSynced) {
					t.Fatal("failed to sync")
				}
			},
		},
		{
			name: "informer-synced-no-pods-gathered-in-dir",
			testFn: func(t *testing.T, httpClient *http.Client) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				configClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				informers := kubeinformers.NewSharedInformerFactoryWithOptions(configClient, 0, kubeinformers.WithNamespace("openshift-authentication-operator"))
				namespacedPodInformer := informers.Core().V1().Pods()
				namespacedPodInformer.Informer()
				informers.Start(ctx.Done())

				timedOutCh := make(chan struct{})
				go func() {
					select {
					case <-time.After(1 * time.Second):
						close(timedOutCh)
					}
				}()
				if !cache.WaitForCacheSync(timedOutCh, namespacedPodInformer.Informer().HasSynced) {
					t.Fatal("failed to sync")
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
