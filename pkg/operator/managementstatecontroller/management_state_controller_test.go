package managementstatecontroller

import (
	"context"
	"testing"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/management"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestOperatorManagementStateController(t *testing.T) {
	testCases := []struct {
		name              string
		initialConditions []operatorv1.OperatorCondition
		managementState   string
		allowUnmanaged    bool
		allowRemove       bool

		expectedFailingStatus bool
		expectedMessage       string
	}{
		{
			name:            "operator in managed state with no restrictions",
			managementState: string(operatorv1.Managed),
			allowRemove:     true,
			allowUnmanaged:  true,
		},
		{
			name:            "operator in unmanaged state with no restrictions",
			managementState: string(operatorv1.Unmanaged),
			allowRemove:     true,
			allowUnmanaged:  true,
		},
		{
			name:                  "operator in unknown state with no restrictions",
			managementState:       string("UnknownState"),
			expectedFailingStatus: true,
			expectedMessage:       `Unsupported management state "UnknownState" for OPERATOR_NAME operator`,
			allowRemove:           true,
			allowUnmanaged:        true,
		},
		{
			name:                  "operator in unmanaged state with unmanaged not allowed",
			managementState:       string(operatorv1.Unmanaged),
			expectedFailingStatus: true,
			expectedMessage:       `Unmanaged is not supported for OPERATOR_NAME operator`,
			allowRemove:           true,
			allowUnmanaged:        false,
		},
		{
			name:                  "operator in removed state with removed  not allowed",
			managementState:       string(operatorv1.Removed),
			expectedFailingStatus: true,
			expectedMessage:       `Removed is not supported for OPERATOR_NAME operator`,
			allowRemove:           false,
			allowUnmanaged:        false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// These test MUST NOT run in parallel due to global vars in management pkg.
			if tc.allowRemove {
				management.SetOperatorRemovable()
			} else {
				management.SetOperatorNotRemovable()
			}
			if tc.allowUnmanaged {
				management.SetOperatorUnmanageable()
			} else {
				management.SetOperatorAlwaysManaged()
			}

			statusClient := &statusClient{
				t: t,
				spec: operatorv1.OperatorSpec{
					ManagementState: operatorv1.ManagementState(tc.managementState),
				},
				status: operatorv1.OperatorStatus{
					Conditions: tc.initialConditions,
				},
			}
			recorder := events.NewInMemoryRecorder("status")
			controller := &ManagementStateController{
				operatorName:   "OPERATOR_NAME",
				operatorClient: statusClient,
			}
			if err := controller.sync(context.TODO(), factory.NewSyncContext("test", recorder)); err != nil {
				t.Errorf("unexpected sync error: %v", err)
				return
			}

			_, result, _, _ := statusClient.GetOperatorState()

			if tc.expectedFailingStatus && result.Conditions[0].Type == "ManagementStateDegraded" && result.Conditions[0].Status == operatorv1.ConditionFalse {
				t.Errorf("expected failing conditions")
				return
			}

			if !tc.expectedFailingStatus && result.Conditions[0].Type == "ManagementStateDegraded" && result.Conditions[0].Status != operatorv1.ConditionFalse {
				t.Errorf("unexpected failing conditions: %#v", result.Conditions)
				return
			}

			if tc.expectedFailingStatus {
				if result.Conditions[0].Message != tc.expectedMessage {
					t.Errorf("expected message %q, got %q", result.Conditions[0].Message, tc.expectedMessage)
				}
			}
		})
	}
}

// OperatorStatusProvider
type statusClient struct {
	t      *testing.T
	spec   operatorv1.OperatorSpec
	status operatorv1.OperatorStatus
}

func (c *statusClient) Informer() cache.SharedIndexInformer {
	c.t.Log("Informer called")
	return nil
}

func (c *statusClient) GetObjectMeta() (*metav1.ObjectMeta, error) {
	panic("missing")
}

func (c *statusClient) GetOperatorState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return &c.spec, &c.status, "", nil
}

func (c *statusClient) GetOperatorStateWithQuorum(ctx context.Context) (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return c.GetOperatorState()
}

func (c *statusClient) UpdateOperatorSpec(context.Context, string, *operatorv1.OperatorSpec) (spec *operatorv1.OperatorSpec, resourceVersion string, err error) {
	panic("missing")
}

func (c *statusClient) UpdateOperatorStatus(ctx context.Context, version string, s *operatorv1.OperatorStatus) (status *operatorv1.OperatorStatus, err error) {
	c.status = *s
	return &c.status, nil
}

func (c *statusClient) ApplyOperatorSpec(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorSpecApplyConfiguration) (err error) {
	return nil
}

func (c *statusClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration) (err error) {
	return nil
}
