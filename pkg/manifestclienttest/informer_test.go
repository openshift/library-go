package manifestclienttest

import (
	"context"
	"net/http"
	"testing"
	"time"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"k8s.io/client-go/tools/cache"

	"github.com/davecgh/go-spew/spew"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
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
