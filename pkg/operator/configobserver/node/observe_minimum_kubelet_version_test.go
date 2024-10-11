package node

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestObserveKubeletMinimumVersion(t *testing.T) {
	type Test struct {
		name                   string
		existingConfig         map[string]interface{}
		expectedObservedConfig map[string]interface{}
		minimumKubeletVersion  string
	}
	tests := []Test{
		{
			name:                   "empty minimumKubeletVersion",
			expectedObservedConfig: map[string]interface{}{},
			minimumKubeletVersion:  "",
		},
		{
			name: "set minimumKubeletVersion",
			expectedObservedConfig: map[string]interface{}{
				"minimumKubeletVersion": string("1.30.0"),
			},
			minimumKubeletVersion: "1.30.0",
		},
		{
			name: "existing minimumKubeletVersion",
			expectedObservedConfig: map[string]interface{}{
				"minimumKubeletVersion": string("1.30.0"),
			},
			existingConfig: map[string]interface{}{
				"minimumKubeletVersion": string("1.29.0"),
			},
			minimumKubeletVersion: "1.30.0",
		},
		{
			name:                   "existing minimumKubeletVersion unset",
			expectedObservedConfig: map[string]interface{}{},
			existingConfig: map[string]interface{}{
				"minimumKubeletVersion": string("1.29.0"),
			},
			minimumKubeletVersion: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// test data
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			configNodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			configNodeIndexer.Add(&configv1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       configv1.NodeSpec{MinimumKubeletVersion: test.minimumKubeletVersion},
			})
			listers := testLister{
				nodeLister: configlistersv1.NewNodeLister(configNodeIndexer),
			}

			// act
			actualObservedConfig, errs := ObserveMinimumKubeletVersion(listers, eventRecorder, test.existingConfig)

			// validate
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			if diff := cmp.Diff(test.expectedObservedConfig, actualObservedConfig); diff != "" {
				t.Fatalf("unexpected configuration, diff = %v", diff)
			}
		})
	}
}
