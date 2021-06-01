package resourceapply

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	migrationv1alpha1 "sigs.k8s.io/kube-storage-version-migrator/pkg/apis/migration/v1alpha1"
	"sigs.k8s.io/kube-storage-version-migrator/pkg/clients/clientset/fake"
)

func TestApplyStorageVersionMigration(t *testing.T) {
	tests := []struct {
		name     string
		existing []runtime.Object
		input    *migrationv1alpha1.StorageVersionMigration

		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &migrationv1alpha1.StorageVersionMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: migrationv1alpha1.StorageVersionMigrationSpec{
					Resource: migrationv1alpha1.GroupVersionResource{
						Group:    "example.com",
						Version:  "v1",
						Resource: "bar",
					},
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "storageversionmigrations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}

				if !actions[1].Matches("create", "storageversionmigrations") {
					t.Error(spew.Sdump(actions))
				}

				expected := &migrationv1alpha1.StorageVersionMigration{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
					Spec: migrationv1alpha1.StorageVersionMigrationSpec{
						Resource: migrationv1alpha1.GroupVersionResource{
							Group:    "example.com",
							Version:  "v1",
							Resource: "bar",
						},
					},
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*migrationv1alpha1.StorageVersionMigration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on missing label",
			existing: []runtime.Object{
				&migrationv1alpha1.StorageVersionMigration{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "foo",
						Labels: map[string]string{"extra": "leave-alone"},
					},
				},
			},
			input: &migrationv1alpha1.StorageVersionMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "foo",
					Labels: map[string]string{"new": "merge"},
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "storageversionmigrations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "storageversionmigrations") {
					t.Error(spew.Sdump(actions))
				}

				expected := &migrationv1alpha1.StorageVersionMigration{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
						Labels: map[string]string{
							"extra": "leave-alone",
							"new":   "merge"},
					},
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*migrationv1alpha1.StorageVersionMigration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on mismatch GVRs",
			existing: []runtime.Object{
				&migrationv1alpha1.StorageVersionMigration{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
					Spec: migrationv1alpha1.StorageVersionMigrationSpec{
						Resource: migrationv1alpha1.GroupVersionResource{
							Group:    "example.com",
							Version:  "v1alpha1",
							Resource: "bar",
						},
					},
				},
			},
			input: &migrationv1alpha1.StorageVersionMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: migrationv1alpha1.StorageVersionMigrationSpec{
					Resource: migrationv1alpha1.GroupVersionResource{
						Group:    "app.example.com",
						Version:  "v1beta1",
						Resource: "barz",
					},
				},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "storageversionmigrations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "storageversionmigrations") {
					t.Error(spew.Sdump(actions))
				}

				expected := &migrationv1alpha1.StorageVersionMigration{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
					Spec: migrationv1alpha1.StorageVersionMigrationSpec{
						Resource: migrationv1alpha1.GroupVersionResource{
							Group:    "app.example.com",
							Version:  "v1beta1",
							Resource: "barz",
						},
					},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*migrationv1alpha1.StorageVersionMigration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyStorageVersionMigration(client, events.NewInMemoryRecorder("test"), test.input)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}

			test.verifyActions(client.Actions(), t)
		})
	}
}
