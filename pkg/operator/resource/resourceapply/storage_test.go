package resourceapply

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/openshift/library-go/pkg/operator/events"
	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

func TestApplyStorageClass(t *testing.T) {
	retain := v1.PersistentVolumeReclaimRetain
	delete := v1.PersistentVolumeReclaimDelete
	immediate := storagev1.VolumeBindingImmediate
	wait := storagev1.VolumeBindingWaitForFirstConsumer

	tests := []struct {
		name     string
		existing []runtime.Object
		input    *storagev1.StorageClass

		expectedModified bool
		expectedFailure  bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class:": "true"}},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class:": "true"}},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on missing label",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"new": "merge"}},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"new": "merge"}},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "don't update because existing object misses TypeMeta",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
			input: &storagev1.StorageClass{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StorageClass",
					APIVersion: "storage.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "don't update because existing object has creationTimestamp",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "foo",
						CreationTimestamp: metav1.Time{Time: time.Now()},
					},
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "don't update because the object has been modified",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "foo",
						Annotations:     map[string]string{"storageclass.kubernetes.io/is-default-class": "false"},
						ResourceVersion: "1",
					},
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Annotations:     map[string]string{"storageclass.kubernetes.io/is-default-class": "true"},
					ResourceVersion: "2",
				},
			},
			expectedModified: false,
			expectedFailure:  true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "don't overwrite default StorageClass annotation if already set",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foo",
						Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "false"},
					},
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"},
				},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "update of mutable AllowVolumeExpansion",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta:        metav1.ObjectMeta{Name: "foo"},
					Provisioner:       "foo",
					ReclaimPolicy:     &retain,
					VolumeBindingMode: &immediate,
					Parameters: map[string]string{
						"foo": "bar",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta:        metav1.ObjectMeta{Name: "foo"},
				Provisioner:       "foo",
				ReclaimPolicy:     &retain,
				VolumeBindingMode: &immediate,
				Parameters: map[string]string{
					"foo": "bar",
				},
				AllowVolumeExpansion: ptr.To(false),
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta:        metav1.ObjectMeta{Name: "foo"},
					Provisioner:       "foo",
					ReclaimPolicy:     &retain,
					VolumeBindingMode: &immediate,
					Parameters: map[string]string{
						"foo": "bar",
					},
					AllowVolumeExpansion: ptr.To(false),
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update of immutable Provisioner",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
					Provisioner: "foo",
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
				Provisioner: "bar",
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				if !actions[2].Matches("create", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
					Provisioner: "bar",
				}
				actual := actions[2].(clienttesting.CreateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update of immutable ReclaimPolicy",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta:    metav1.ObjectMeta{Name: "foo"},
					Provisioner:   "foo",
					ReclaimPolicy: &retain,
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta:    metav1.ObjectMeta{Name: "foo"},
				Provisioner:   "foo",
				ReclaimPolicy: &delete,
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				if !actions[2].Matches("create", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta:    metav1.ObjectMeta{Name: "foo"},
					Provisioner:   "foo",
					ReclaimPolicy: &delete,
				}
				actual := actions[2].(clienttesting.CreateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update of immutable VolumeBindingMode",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta:        metav1.ObjectMeta{Name: "foo"},
					Provisioner:       "foo",
					VolumeBindingMode: &immediate,
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta:        metav1.ObjectMeta{Name: "foo"},
				Provisioner:       "foo",
				VolumeBindingMode: &wait,
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				if !actions[2].Matches("create", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta:        metav1.ObjectMeta{Name: "foo"},
					Provisioner:       "foo",
					VolumeBindingMode: &wait,
				}
				actual := actions[2].(clienttesting.CreateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update of immutable Parameters",
			existing: []runtime.Object{
				&storagev1.StorageClass{
					ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
					Provisioner: "foo",
					Parameters: map[string]string{
						"foo": "bar",
					},
				},
			},
			input: &storagev1.StorageClass{
				ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
				Provisioner: "foo",
				Parameters: map[string]string{
					"foo": "baz",
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "storageclasses") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				if !actions[2].Matches("create", "storageclasses") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.StorageClass{
					ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
					Provisioner: "foo",
					Parameters: map[string]string{
						"foo": "baz",
					},
				}
				actual := actions[2].(clienttesting.CreateAction).GetObject().(*storagev1.StorageClass)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyStorageClass(context.TODO(), client.StorageV1(), events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now())), test.input)
			if err != nil && !test.expectedFailure {
				t.Fatal(err)
			}
			if err == nil && test.expectedFailure {
				t.Errorf("expected failure, but the call succeeded")
			}
			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}
			test.verifyActions(client.Actions(), t)
		})
	}
}

func TestApplyCSIDriver(t *testing.T) {
	tests := []struct {
		name     string
		existing []*storagev1.CSIDriver
		input    *storagev1.CSIDriver
		// Compute hash of input.Spec and use it as the existing.annotations[specHashAnnotation]
		// Useful for simulating the API server clearing some alpha/beta fields in existing.Spec.
		existingHashFromInput bool

		expectedModified bool
		expectedError    error
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Annotations: map[string]string{"my.csi.driver/foo": "bar"}},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.CSIDriver{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Annotations: map[string]string{"my.csi.driver/foo": "bar"}},
				}
				SetSpecHashAnnotation(&expected.ObjectMeta, expected.Spec)
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*storagev1.CSIDriver)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on missing label",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"new": "merge"}},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.CSIDriver{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"new": "merge"}},
				}
				SetSpecHashAnnotation(&expected.ObjectMeta, expected.Spec)
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*storagev1.CSIDriver)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "mutated spec",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: storagev1.CSIDriverSpec{
						AttachRequired: ptr.To(true),
						PodInfoOnMount: ptr.To(true),
					},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: storagev1.CSIDriverSpec{
					AttachRequired: ptr.To(false),
					PodInfoOnMount: ptr.To(false),
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
				if !actions[2].Matches("create", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "no change",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: storagev1.CSIDriverSpec{
						AttachRequired: ptr.To(true),
						PodInfoOnMount: ptr.To(true),
					},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: storagev1.CSIDriverSpec{
					AttachRequired: ptr.To(true),
					PodInfoOnMount: ptr.To(true),
				},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "ephemeral volume mode with required label",
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{"my.csi.driver/foo": "bar"},
					Labels:      map[string]string{csiInlineVolProfileLabel: "restricted"},
				},
				Spec: storagev1.CSIDriverSpec{
					VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
						storagev1.VolumeLifecycleEphemeral,
					},
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.CSIDriver{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foo",
						Annotations: map[string]string{"my.csi.driver/foo": "bar"},
						Labels:      map[string]string{csiInlineVolProfileLabel: "restricted"},
					},
					Spec: storagev1.CSIDriverSpec{
						VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
							storagev1.VolumeLifecycleEphemeral,
						},
					},
				}
				SetSpecHashAnnotation(&expected.ObjectMeta, expected.Spec)
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*storagev1.CSIDriver)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "ephemeral volume mode missing required label",
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{"my.csi.driver/foo": "bar"},
				},
				Spec: storagev1.CSIDriverSpec{
					VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
						storagev1.VolumeLifecycleEphemeral,
					},
				},
			},
			expectedModified: false,
			expectedError:    fmt.Errorf("CSIDriver foo supports Ephemeral volume lifecycle but is missing required label security.openshift.io/csi-ephemeral-volume-profile"),
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
		},
		{
			name: "exempt label with missing labels on original object",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foo",
						Annotations: map[string]string{"my.csi.driver/foo": "bar"},
						Labels: map[string]string{
							csiInlineVolProfileLabel: "restricted",
						},
					},
					Spec: storagev1.CSIDriverSpec{
						VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
							storagev1.VolumeLifecyclePersistent,
						},
					},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{"my.csi.driver/foo": "bar"},
				},
				Spec: storagev1.CSIDriverSpec{
					VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
						storagev1.VolumeLifecyclePersistent,
					},
				},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "exempt label with differing value should not be overwritten during update",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foo",
						Annotations: map[string]string{"my.csi.driver/foo": "bar"},
						Labels:      map[string]string{csiInlineVolProfileLabel: "restricted"},
					},
					Spec: storagev1.CSIDriverSpec{
						VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
							storagev1.VolumeLifecycleEphemeral,
						},
					},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{"my.csi.driver/foo": "bar"},
					Labels:      map[string]string{csiInlineVolProfileLabel: "privileged"},
				},
				Spec: storagev1.CSIDriverSpec{
					VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
						storagev1.VolumeLifecycleEphemeral,
					},
				},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "missing exempt labels should be added with default value during update",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foo",
						Annotations: map[string]string{"my.csi.driver/foo": "bar"},
					},
					Spec: storagev1.CSIDriverSpec{
						VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
							storagev1.VolumeLifecycleEphemeral,
						},
					},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo",
					Annotations: map[string]string{"my.csi.driver/foo": "bar"},
					Labels:      map[string]string{csiInlineVolProfileLabel: "restricted"},
				},
				Spec: storagev1.CSIDriverSpec{
					VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
						storagev1.VolumeLifecycleEphemeral,
					},
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
				expected := &storagev1.CSIDriver{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foo",
						Annotations: map[string]string{"my.csi.driver/foo": "bar"},
						Labels:      map[string]string{csiInlineVolProfileLabel: "restricted"},
					},
					Spec: storagev1.CSIDriverSpec{
						VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{
							storagev1.VolumeLifecycleEphemeral,
						},
					},
				}
				SetSpecHashAnnotation(&expected.ObjectMeta, expected.Spec)
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*storagev1.CSIDriver)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "alphaFieldsSaved: same spec hash but missing alpha field triggers update",
			existing: []*storagev1.CSIDriver{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
					Spec: storagev1.CSIDriverSpec{
						AttachRequired: ptr.To(true),
						PodInfoOnMount: ptr.To(true),
						// NodeAllocatableUpdatePeriodSeconds is missing (simulating API server cleared it)
					},
				},
			},
			input: &storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storagev1.CSIDriverSpec{
					AttachRequired:                     ptr.To(true),
					PodInfoOnMount:                     ptr.To(true),
					NodeAllocatableUpdatePeriodSeconds: ptr.To[int64](30),
				},
			},
			existingHashFromInput: true,
			expectedModified:      true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "csidrivers") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "csidrivers") {
					t.Error(spew.Sdump(actions))
				}
				// Verify that the update includes the alpha field
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*storagev1.CSIDriver)
				if actual.Spec.NodeAllocatableUpdatePeriodSeconds == nil || *actual.Spec.NodeAllocatableUpdatePeriodSeconds != 30 {
					t.Errorf("expected NodeAllocatableUpdatePeriodSeconds to be 30, got %v", actual.Spec.NodeAllocatableUpdatePeriodSeconds)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objs := make([]runtime.Object, len(test.existing))
			for i, csiDriver := range test.existing {
				// Add spec hash annotation
				if test.existingHashFromInput {
					SetSpecHashAnnotation(&csiDriver.ObjectMeta, test.input.Spec)
				} else {
					// Add spec hash annotation based on existing spec
					SetSpecHashAnnotation(&csiDriver.ObjectMeta, csiDriver.Spec)
				}
				// Convert *CSIDriver to *Object
				objs[i] = csiDriver
			}

			client := fake.NewSimpleClientset(objs...)
			_, actualModified, err := ApplyCSIDriver(context.TODO(), client.StorageV1(), events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now())), test.input)
			if err != nil {
				if test.expectedError == nil {
					t.Fatalf("%s: returned error: %v", test.name, err)
				}

				if !strings.Contains(err.Error(), test.expectedError.Error()) {
					t.Fatalf("%s: the expected error %v, got %v", test.name, test.expectedError, err)
				}
			}

			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}
			test.verifyActions(client.Actions(), t)
		})
	}
}
