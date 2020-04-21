package factory

import (
	"fmt"
	"strings"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestHandleErrorConditions(t *testing.T) {
	asDegradedError := func(err error, t *testing.T) {
		if !IsDegradedConditionError(err) {
			t.Errorf("expected degraded error, got %v", err)
		}
	}
	asUnavailableError := func(err error, t *testing.T) {
		if !IsAvailableConditionError(err) {
			t.Errorf("expected unavailable error, got %v", err)
		}
	}
	asNotUpgradeableError := func(err error, t *testing.T) {
		if !IsUpgradeableConditionError(err) {
			t.Errorf("expected not upgradeable error, got %v", err)
		}
	}

	ctx := NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))

	tests := []struct {
		name                   string
		syncErr                error
		knownConditions        sets.String
		expectedCondition      *operatorv1.OperatorCondition
		expectedConditionNames sets.String
		evalError              func(error, *testing.T)
	}{
		{
			name:            "degraded",
			syncErr:         ctx.NewDegradedConditionError("OperatorDegraded", "TestReason", "TestMessage"),
			knownConditions: sets.NewString("OperatorDegraded"),
			evalError:       asDegradedError,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "OperatorDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "TestReason",
				Message: "TestMessage",
			},
		},
		{
			name:            "degraded unknown",
			syncErr:         ctx.NewDegradedConditionError("OperatorDegraded", "TestReason", "TestMessage"),
			knownConditions: sets.NewString(),
			evalError: func(err error, t *testing.T) {
				if !strings.Contains(err.Error(), "unknown condition type") {
					t.Errorf("expected unknown condition type error, got %q", err)
				}
			},
		},
		{
			name:            "degraded multiple",
			syncErr:         ctx.NewDegradedConditionError("Operator", "TestReason", "TestMessage"),
			knownConditions: sets.NewString("OperatorDegraded", "AnotherOperatorDegraded"),
			evalError:       asDegradedError,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "OperatorDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "TestReason",
				Message: "TestMessage",
			},
		},
		{
			name:            "available",
			syncErr:         ctx.NewAvailableConditionError("OperatorAvailable", "TestReason", "TestMessage"),
			knownConditions: sets.NewString("OperatorAvailable"),
			evalError:       asUnavailableError,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "OperatorAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "TestReason",
				Message: "TestMessage",
			},
		},
		{
			name:            "upgradeable",
			syncErr:         ctx.NewUpgradeableConditionError("OperatorUpgradeable", "TestReason", "TestMessage"),
			knownConditions: sets.NewString("OperatorUpgradeable"),
			evalError:       asNotUpgradeableError,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "OperatorUpgradeable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "TestReason",
				Message: "TestMessage",
			},
		},
		{
			name:            "upgradeable defaulted",
			syncErr:         nil,
			knownConditions: sets.NewString("OperatorUpgradeable"),
			expectedCondition: &operatorv1.OperatorCondition{
				Type:   "OperatorUpgradeable",
				Status: operatorv1.ConditionTrue,
				Reason: "AsExpected",
			},
		},
		{
			name:            "degraded on error",
			syncErr:         fmt.Errorf("sync error"),
			knownConditions: sets.NewString("TestDegraded"), // ControllerName+Degraded
			evalError: func(err error, t *testing.T) {
				if err.Error() != "sync error" {
					t.Errorf("expected original sync error, got %v", err)
				}
			},
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "TestDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "SyncError",
				Message: "sync error",
			},
		},
		{
			name:            "aggregated degraded",
			syncErr:         errors.NewAggregate([]error{ctx.NewDegradedConditionError("FirstOperator", "FirstReason", "message"), ctx.NewDegradedConditionError("SecondOperator", "SecondReason", "message")}),
			knownConditions: sets.NewString("FirstOperatorDegraded", "SecondOperatorDegraded"),
			evalError: func(err error, t *testing.T) {
				if strings.Contains(err.Error(), "FirstReason") && strings.Contains(err.Error(), "SecondReason") {
					return
				}
				t.Errorf("expected error to have both conditions, got %#v", err.Error())
			},
			expectedConditionNames: sets.NewString("FirstOperatorDegraded", "SecondOperatorDegraded"),
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "FirstOperatorDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "FirstReason",
				Message: "message",
			},
		},
		{
			name:            "aggregated multiple conditions",
			syncErr:         errors.NewAggregate([]error{ctx.NewDegradedConditionError("FirstOperator", "FirstReason", "message"), ctx.NewAvailableConditionError("NotAvailable", "AvailableReason", "message")}),
			knownConditions: sets.NewString("FirstOperatorDegraded", "NotAvailable"),
			evalError: func(err error, t *testing.T) {
				if strings.Contains(err.Error(), "FirstReason") && strings.Contains(err.Error(), "AvailableReason") {
					return
				}
				t.Errorf("expected error to have both conditions, got %#v", err.Error())
			},
			expectedConditionNames: sets.NewString("FirstOperatorDegraded", "NotAvailable"),
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "NotAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "AvailableReason",
				Message: "message",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil)

			err := handleErrorConditions(client, "Test", test.knownConditions, test.syncErr)
			if test.evalError != nil {
				test.evalError(err, t)
			} else if err != nil {
				t.Fatal(err)
			}

			_, status, _, _ := client.GetOperatorState()

			if test.expectedCondition != nil {
				currentCondition := v1helpers.FindOperatorCondition(status.Conditions, test.expectedCondition.Type)
				if currentCondition == nil {
					t.Fatalf("expected condition %q not found", test.expectedCondition.Type)
				}
				if currentCondition.Reason != test.expectedCondition.Reason {
					t.Errorf("expected condition reason %q is %q", test.expectedCondition.Reason, currentCondition.Reason)
				}
				if currentCondition.Message != test.expectedCondition.Message {
					t.Errorf("expected condition message %q is %q", test.expectedCondition.Message, currentCondition.Message)
				}
				if currentCondition.Status != test.expectedCondition.Status {
					t.Errorf("expected condition status %q is %q", test.expectedCondition.Status, currentCondition.Status)
				}
			}

			for _, c := range status.Conditions {
				if test.expectedCondition != nil && test.expectedConditionNames.Len() == 0 && c.Type == test.expectedCondition.Type {
					continue
				}
				if test.expectedConditionNames.Has(c.Type) {
					continue
				}
				if c.Reason != "AsExpected" {
					t.Errorf("expected condition %q reason to be AsExpected, got %q", c.Type, c.Reason)
				}
				expectedStatus := operatorv1.ConditionTrue
				if strings.HasSuffix(c.Type, "Degraded") {
					expectedStatus = operatorv1.ConditionFalse
				}
				if c.Status != expectedStatus {
					t.Errorf("expected condition %q status to be %q, got %q", c.Type, expectedStatus, c.Status)
				}
			}

		})
	}
}
