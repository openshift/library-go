package controllermanager

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	configlistersv1alpha1 "github.com/openshift/client-go/config/listers/config/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestObserveVolumeForceDetach(t *testing.T) {
	tests := []struct {
		name string
		// controllerManager is added to the indexer when non-nil
		controllerManager *configv1alpha1.ControllerManager
		existingConfig    map[string]interface{}
		expectedFlag      []string
		expectEmptyConfig bool
	}{
		{
			name:              "object missing",
			existingConfig:    map[string]interface{}{},
			expectEmptyConfig: true,
		},
		{
			name: "spec nil",
			controllerManager: &configv1alpha1.ControllerManager{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			},
			existingConfig:    map[string]interface{}{},
			expectEmptyConfig: true,
		},
		{
			name: "field unset",
			controllerManager: &configv1alpha1.ControllerManager{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       &configv1alpha1.ControllerManagerSpec{},
			},
			existingConfig:    map[string]interface{}{},
			expectEmptyConfig: true,
		},
		{
			name: "out-of-service taint only maps to true",
			controllerManager: &configv1alpha1.ControllerManager{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: &configv1alpha1.ControllerManagerSpec{
					VolumeForceDetach: configv1alpha1.VolumeForceDetachOnOutOfServiceTaintOnly,
				},
			},
			existingConfig: map[string]interface{}{},
			expectedFlag:   []string{"true"},
		},
		{
			name: "on unmount timeout maps to false",
			controllerManager: &configv1alpha1.ControllerManager{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: &configv1alpha1.ControllerManagerSpec{
					VolumeForceDetach: configv1alpha1.VolumeForceDetachOnUnmountTimeout,
				},
			},
			existingConfig: map[string]interface{}{},
			expectedFlag:   []string{"false"},
		},
		{
			name: "replaces previous flag value",
			controllerManager: &configv1alpha1.ControllerManager{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: &configv1alpha1.ControllerManagerSpec{
					VolumeForceDetach: configv1alpha1.VolumeForceDetachOnUnmountTimeout,
				},
			},
			existingConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"disable-force-detach-on-timeout": []interface{}{"true"},
				},
			},
			expectedFlag: []string{"false"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.controllerManager != nil {
				if err := indexer.Add(tt.controllerManager); err != nil {
					t.Fatal(err)
				}
			}
			listers := testLister{
				controllerManagerLister: configlistersv1alpha1.NewControllerManagerLister(indexer),
			}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			gotConfig, errs := ObserveVolumeForceDetach(listers, recorder, tt.existingConfig)
			if len(errs) > 0 {
				t.Errorf("expected no errors, got %v", errs)
			}

			if tt.expectEmptyConfig {
				if len(gotConfig) != 0 {
					t.Fatalf("expected empty config, got %v", gotConfig)
				}
				return
			}

			gotFlag, _, err := unstructured.NestedStringSlice(gotConfig, volumeForceDetachFlagPath...)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotFlag, tt.expectedFlag) {
				t.Fatalf("got = %v, want %v", gotFlag, tt.expectedFlag)
			}
		})
	}
}
