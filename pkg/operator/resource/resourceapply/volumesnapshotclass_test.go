package resourceapply

import (
	"fmt"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	fakeVolumeSnapshotClassTemplate = `apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: standard-csi
  annotations:
    snapshot.storage.kubernetes.io/is-default-class: "true"
driver: %v
deletionPolicy: %v
parameters:
  %v
`
)

func readVolumeSnapshotClassFromBytes(volumeSnapshotClassBytes []byte) *unstructured.Unstructured {
	volumeSnapshotClassJSON, err := yaml.YAMLToJSON(volumeSnapshotClassBytes)
	if err != nil {
		panic(err)
	}
	volumeSnapshotClassObj, err := runtime.Decode(unstructured.UnstructuredJSONScheme, volumeSnapshotClassJSON)
	if err != nil {
		panic(err)
	}
	required, ok := volumeSnapshotClassObj.(*unstructured.Unstructured)
	if !ok {
		panic("unexpected object")
	}
	return required
}

func TestApplyVolumeSnapshotClassUpdate(t *testing.T) {
	dynamicScheme := runtime.NewScheme()
	dynamicScheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: "snapshot.storage.k8s.io", Version: "v1", Kind: "VolumeSnapshotClass"}, &unstructured.Unstructured{})

	cases := []struct {
		name             string
		existing         string
		required         string
		expectedModified bool
		expectedErr      bool
	}{
		{
			name:     "No changes",
			existing: fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required: fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
		},
		{
			name:             "Update parameters",
			existing:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: true"),
			expectedModified: true,
		},
		{
			name:             "Add parameters",
			existing:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: true\n  fsType: ext4"),
			expectedModified: true,
		},
		{
			name:             "Overwrite parameters",
			existing:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "fsType: ext4"),
			expectedModified: true,
		},
		{
			name:             "Update deletion policy",
			existing:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Retain", "force-create: false"),
			expectedModified: true,
		},
		{
			name:             "Update driver",
			existing:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "ashes.csi.openstack.org", "Delete", "force-create: false"),
			expectedModified: true,
		},
		{
			name:             "Update all",
			existing:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:         fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "ashes.csi.openstack.org", "Retain", "force-create: true"),
			expectedModified: true,
		},
		{
			name:        "Invalid parameters",
			existing:    fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "force-create: false"),
			required:    fmt.Sprintf(fakeVolumeSnapshotClassTemplate, "cinder.csi.openstack.org", "Delete", "- INVALID"),
			expectedErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClient(dynamicScheme, readVolumeSnapshotClassFromBytes([]byte(tc.existing)))

			required := resourceread.ReadUnstructuredOrDie([]byte(tc.required))

			_, modified, err := ApplyVolumeSnapshotClass(dynamicClient, events.NewInMemoryRecorder("volumesnapshotclass-test"), required)
			if tc.expectedErr {
				if err != nil {
					return
				} else {
					t.Fatalf("expecting error, got: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !modified && tc.expectedModified {
				t.Fatalf("expected the volume snapshot class will be modified, it was not")
			}

			if modified {
				if len(dynamicClient.Actions()) != 2 {
					t.Fatalf("expected 2 actions, got %d", len(dynamicClient.Actions()))
				}

				_, isUpdate := dynamicClient.Actions()[1].(clienttesting.UpdateAction)
				if !isUpdate {
					t.Fatalf("expected second action to be update, got %+v", dynamicClient.Actions()[1])
				}

				updateAction, isUpdate := dynamicClient.Actions()[1].(clienttesting.UpdateAction)
				if !isUpdate {
					t.Fatalf("expected second action to be update, got %+v", dynamicClient.Actions()[1])
				}
				updatedVolumeSnapshotClassJSON, err := updateAction.GetObject().(*unstructured.Unstructured).MarshalJSON()
				if err != nil {
					t.Fatal("cannot decode updated volumesnapshotclass object")
				}

				requiredVolumeSnapshotClassJSON, err := required.MarshalJSON()
				if err != nil {
					t.Fatal("cannot decode required volume snapshot class object")
				}

				if string(updatedVolumeSnapshotClassJSON) != string(requiredVolumeSnapshotClassJSON) {
					t.Fatal("updated volume snapshot class object doesn't match the required one")
				}
			}
		})
	}
}
