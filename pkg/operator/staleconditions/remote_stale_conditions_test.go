package staleconditions

import (
	"context"
	"fmt"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestSync(t *testing.T) {
	testCases := []struct {
		name               string
		conditionsToRemove []string
		initialObject      *operatorv1.Authentication
		verifyJSONPatch    func(*jsonpatch.PatchSet) error
	}{

		{
			name:               "should not try to remove non-existent conditions",
			conditionsToRemove: []string{"FakeCondition1"},
			initialObject: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{{Type: "FakeCondition2"}},
					},
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New()
				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
		},
		{
			name:               "should remove condition",
			conditionsToRemove: []string{"FakeCondition"},
			initialObject: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{{Type: "FakeCondition"}},
					},
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/conditions/0", jsonpatch.NewTestCondition("/status/conditions/0/type", "FakeCondition"))
				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
		},
		{
			name:               "should remove multiple conditions",
			conditionsToRemove: []string{"FakeCondition2", "FakeCondition3"},
			initialObject: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{
							{Type: "FakeCondition1"},
							{Type: "FakeCondition2"},
							{Type: "FakeCondition3"},
						},
					},
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/conditions/1", jsonpatch.NewTestCondition("/status/conditions/1/type", "FakeCondition2")).
					WithRemove("/status/conditions/1", jsonpatch.NewTestCondition("/status/conditions/1/type", "FakeCondition3"))
				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
		},
		{
			name:               "should remove multiple conditions in the same order",
			conditionsToRemove: []string{"FakeCondition3", "FakeCondition2"},
			initialObject: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{
							{Type: "FakeCondition1"},
							{Type: "FakeCondition2"},
							{Type: "FakeCondition3"},
						},
					},
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/conditions/1", jsonpatch.NewTestCondition("/status/conditions/1/type", "FakeCondition2")).
					WithRemove("/status/conditions/1", jsonpatch.NewTestCondition("/status/conditions/1/type", "FakeCondition3"))
				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
		},
		{
			name:               "should remove single condition",
			conditionsToRemove: []string{"FakeCondition1", "FakeCondition4"},
			initialObject: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{
							{Type: "FakeCondition1"},
							{Type: "FakeCondition2"},
							{Type: "FakeCondition3"},
						},
					},
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/conditions/0", jsonpatch.NewTestCondition("/status/conditions/0/type", "FakeCondition1"))
				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")
			operatorClient := v1helpers.NewFakeOperatorClient(&tc.initialObject.Spec.OperatorSpec, &tc.initialObject.Status.OperatorStatus, nil)

			controller := NewRemoveStaleConditionsController(
				"operatorName",
				tc.conditionsToRemove,
				operatorClient,
				recorder,
			)

			err := controller.Sync(context.TODO(), factory.NewSyncContext("test", recorder))
			if err != nil {
				t.Fatalf("controller failed to sync: %v", err)
			}

			if err := tc.verifyJSONPatch(operatorClient.GetPatchedOperatorStatus()); err != nil {
				t.Errorf("%s: failed to verify json patch: %v", tc.name, err)
			}
		})
	}
}

func validateJSONPatch(expected, actual *jsonpatch.PatchSet) error {
	expectedSerializedPatch, err := expected.Marshal()
	if err != nil {
		return err
	}
	actualSerializedPatch := []byte("null")
	if actual != nil {
		actualSerializedPatch, err = actual.Marshal()
		if err != nil {
			return err
		}
	}
	if string(expectedSerializedPatch) != string(actualSerializedPatch) {
		return fmt.Errorf("incorrect JSONPatch, expected = %s, got = %s", string(expectedSerializedPatch), string(actualSerializedPatch))
	}
	return nil
}
