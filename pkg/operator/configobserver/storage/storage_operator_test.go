package storage

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	opv1 "github.com/openshift/api/operator/v1"
	oplistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type testLister struct {
	lister oplistersv1.StorageLister
}

func (l testLister) StorageLister() oplistersv1.StorageLister {
	return l.lister
}

func (l testLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l testLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}

func TestObserveStorageOperator(t *testing.T) {
	configPath := []string{"openshift", "storage"}

	tests := []struct {
		name           string
		storageSpec    opv1.StorageSpec
		previous       map[string]string
		expected       map[string]interface{}
		expectedError  []error
		eventsExpected int
	}{
		{
			name:          "all unset",
			storageSpec:   opv1.StorageSpec{},
			expected:      map[string]interface{}{},
			expectedError: []error{},
		},
		{
			name: "when vSphere CSI migration is disabled",
			storageSpec: opv1.StorageSpec{
				VSphereStorageDriver: opv1.LegacyDeprecatedInTreeDriver,
			},
			expected:      map[string]interface{}{},
			expectedError: []error{},
		},
		{
			name: "when vSphere CSI migration is enabled",
			storageSpec: opv1.StorageSpec{
				VSphereStorageDriver: opv1.CSIWithMigrationDriver,
			},
			expected: map[string]interface{}{
				"openshift": map[string]interface{}{
					"storage": map[string]interface{}{
						"OPENSHIFT_DO_VSPHERE_MIGRATION": "true",
					},
				},
			},
			expectedError:  []error{},
			eventsExpected: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			indexer.Add(&opv1.Storage{
				ObjectMeta: metav1.ObjectMeta{Name: storageOperatorName},
				Spec:       tt.storageSpec,
			})
			listers := testLister{
				lister: oplistersv1.NewStorageLister(indexer),
			}
			eventRecorder := events.NewInMemoryRecorder("")

			initialExistingConfig := map[string]interface{}{}

			observeFn := NewStorageObserveFunc(configPath)

			got, errorsGot := observeFn(listers, eventRecorder, initialExistingConfig)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("observeStorageFlags.ObserveStorageOperator() got = %v, want %v", got, tt.expected)
			}
			if !reflect.DeepEqual(errorsGot, tt.expectedError) {
				t.Errorf("observeStorageFlags.ObserveStorageOperator() errorsGot = %v, want %v", errorsGot, tt.expectedError)
			}
			if events := eventRecorder.Events(); len(events) != tt.eventsExpected {
				t.Errorf("expected %d events, but got %d: %v", tt.eventsExpected, len(events), events)
			}
		})
	}
}
