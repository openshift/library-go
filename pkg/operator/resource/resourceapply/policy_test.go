package resourceapply

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/openshift/library-go/pkg/operator/events"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"testing"
	"time"
)

func TestApplyPodDisruptionBudget(t *testing.T) {
	tests := []struct {
		name     string
		existing []runtime.Object
		input    *policyv1.PodDisruptionBudget

		expectedModified bool
		shouldDelete     bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "abc"},
			},

			expectedModified: true,
			shouldDelete:     false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
				expected := &policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "abc"},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*policyv1.PodDisruptionBudget)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on missing label",
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				},
			},
			input: &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"new": "merge"}},
			},
			expectedModified: true,
			shouldDelete:     false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
				expected := &policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"new": "merge"}},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*policyv1.PodDisruptionBudget)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "don't update because existing object misses TypeMeta",
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
			input: &policyv1.PodDisruptionBudget{
				TypeMeta: metav1.TypeMeta{
					Kind:       "PodDisruptionBudget",
					APIVersion: "policy/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedModified: false,
			shouldDelete:     false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "don't update because existing object has creationTimestamp",
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "foo",
						CreationTimestamp: metav1.Time{Time: time.Now()},
					},
				},
			},
			input: &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedModified: false,
			shouldDelete:     false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "delete PDB",
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			input: &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "abc"},
			},
			expectedModified: true,
			shouldDelete:     true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyPodDisruptionBudget(client.PolicyV1(), test.shouldDelete, events.NewInMemoryRecorder("test"), test.input)
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
