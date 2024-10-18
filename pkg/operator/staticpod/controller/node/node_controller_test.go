package node

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func fakeMasterNode(name string) *corev1.Node {
	n := &corev1.Node{}
	n.Name = name
	n.Labels = map[string]string{
		"node-role.kubernetes.io/master": "",
	}

	return n
}

func makeNodeNotReady(node *corev1.Node) *corev1.Node {
	return addNodeReadyCondition(node, corev1.ConditionFalse)
}

func makeNodeReady(node *corev1.Node) *corev1.Node {
	return addNodeReadyCondition(node, corev1.ConditionTrue)
}

func addNodeReadyCondition(node *corev1.Node, status corev1.ConditionStatus) *corev1.Node {
	con := corev1.NodeCondition{}
	con.Type = corev1.NodeReady
	con.Status = status
	con.Reason = "TestReason"
	con.Message = "test message"
	con.LastTransitionTime = metav1.Time{Time: time.Date(2018, 01, 12, 22, 51, 48, 324359102, time.UTC)}
	node.Status.Conditions = append(node.Status.Conditions, con)
	return node
}

func validateNodeControllerDegradedCondition(actualConditions []operatorv1.OperatorCondition, expectedCondition operatorv1.OperatorCondition) error {
	if len(actualConditions) != 1 {
		return fmt.Errorf("expected exaclty 1 condition, got %d", len(actualConditions))
	}

	actualCondition := actualConditions[0]

	if !cmp.Equal(actualCondition, expectedCondition) {
		return fmt.Errorf("incorrect condition received:\n%s", cmp.Diff(actualCondition, expectedCondition))
	}
	return nil
}

func validateJSONPatch(expected, actual *jsonpatch.PatchSet) error {
	expectedSerializedPatch, err := expected.Marshal()
	if err != nil {
		return err
	}
	actualSerializedPatch, err := actual.Marshal()
	if err != nil {
		return err
	}

	if string(expectedSerializedPatch) != string(actualSerializedPatch) {
		return fmt.Errorf("incorrect JSONPatch, expected = %s, got = %s", string(expectedSerializedPatch), string(actualSerializedPatch))
	}
	return nil
}

func TestNodeControllerDegradedConditionType(t *testing.T) {
	scenarios := []struct {
		name                    string
		masterNodes             []runtime.Object
		existingNodeStatuses    []operatorv1.NodeStatus
		existingConditions      []operatorv1.OperatorCondition
		triggerStatusApplyError error

		verifyNodeStatus        func([]operatorv1.OperatorCondition) error
		verifyJSONPatch         func(*jsonpatch.PatchSet) error
		verifyKubeClientActions func(actions []clientgotesting.Action) error
	}{
		{
			name:        "scenario 1: one unhealthy master node is reported",
			masterNodes: []runtime.Object{makeNodeNotReady(fakeMasterNode("test-node-1")), makeNodeReady(fakeMasterNode("test-node-2"))},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionTrue
				expectedCondition.Message = `The master nodes not ready: node "test-node-1" not ready since 2018-01-12 22:51:48.324359102 +0000 UTC because TestReason (test message)`

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 2: all master nodes are healthy",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-1")), makeNodeReady(fakeMasterNode("test-node-2"))},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 3: multiple master nodes are unhealthy",
			masterNodes: []runtime.Object{makeNodeNotReady(fakeMasterNode("test-node-1")), makeNodeReady(fakeMasterNode("test-node-2")), makeNodeNotReady(fakeMasterNode("test-node-3"))},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionTrue
				expectedCondition.Message = `The master nodes not ready: node "test-node-1" not ready since 2018-01-12 22:51:48.324359102 +0000 UTC because TestReason (test message), node "test-node-3" not ready since 2018-01-12 22:51:48.324359102 +0000 UTC because TestReason (test message)`

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 4: Ready condition not present in status block",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-1")), fakeMasterNode("test-node-2")},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionTrue
				expectedCondition.Message = `The master nodes not ready: node "test-node-2" not ready, no Ready condition found in status block`

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 5: a JSON patch is created when two master nodes were removed",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-2")), makeNodeReady(fakeMasterNode("test-node-4"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-1")).
					WithRemove("/status/nodeStatuses/1", jsonpatch.NewTestCondition("/status/nodeStatuses/1/nodeName", "test-node-3"))

				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 6: failed JSON patch is reported as degraded condition",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-2")), makeNodeReady(fakeMasterNode("test-node-4"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			triggerStatusApplyError: fmt.Errorf("nasty err"),
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodeNotRemoved"
				expectedCondition.Status = operatorv1.ConditionTrue
				expectedCondition.Message = "failed applying JSONPatch, err: nasty err"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 7: a JSON patch is created when master node was removed",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-2")), makeNodeReady(fakeMasterNode("test-node-4"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/nodeStatuses/1", jsonpatch.NewTestCondition("/status/nodeStatuses/1/nodeName", "test-node-3"))

				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 8: a JSON patch is created when master node was removed at index 0",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-3")), makeNodeReady(fakeMasterNode("test-node-4"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-2"))

				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 9: a JSON patch is created when all master node were removed",
			masterNodes: []runtime.Object{},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-1")).
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-2")).
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-3")).
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-4"))

				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 10: a JSON patch is created when three master nodes were removed",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-2"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-1")).
					WithRemove("/status/nodeStatuses/1", jsonpatch.NewTestCondition("/status/nodeStatuses/1/nodeName", "test-node-3")).
					WithRemove("/status/nodeStatuses/1", jsonpatch.NewTestCondition("/status/nodeStatuses/1/nodeName", "test-node-4"))

				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 11: a JSON patch is created when odd master nodes were removed",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-2")), makeNodeReady(fakeMasterNode("test-node-4"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-3",
				},
				{
					NodeName: "test-node-4",
				},
			},
			verifyJSONPatch: func(actualJSONPatch *jsonpatch.PatchSet) error {
				expectedJSONPatch := jsonpatch.New().
					WithRemove("/status/nodeStatuses/0", jsonpatch.NewTestCondition("/status/nodeStatuses/0/nodeName", "test-node-1")).
					WithRemove("/status/nodeStatuses/1", jsonpatch.NewTestCondition("/status/nodeStatuses/1/nodeName", "test-node-3"))

				return validateJSONPatch(expectedJSONPatch, actualJSONPatch)
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},

		{
			name:        "scenario 12: MasterNodesReadyChanged is recorded when the previous condition was MasterNodeNotRemoved",
			masterNodes: []runtime.Object{makeNodeReady(fakeMasterNode("test-node-2")), makeNodeReady(fakeMasterNode("test-node-4"))},
			existingNodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-2",
				},
				{
					NodeName: "test-node-4",
				},
			},
			existingConditions: []operatorv1.OperatorCondition{
				{
					Type:    condition.NodeControllerDegradedConditionType,
					Reason:  "MasterNodeNotRemoved",
					Status:  operatorv1.ConditionTrue,
					Message: "failed applying JSONPatch, err: nasty err",
				},
			},
			verifyKubeClientActions: func(actions []clientgotesting.Action) error {
				var validatedEvent bool
				expectedEvent := &corev1.Event{
					Reason:  "MasterNodesReadyChanged",
					Message: "All master nodes are ready",
					Type:    "Normal",
					Count:   1,
				}
				for _, action := range actions {
					if action.GetVerb() == "create" {
						createAction := action.(clientgotesting.CreateAction)
						createdEvent := createAction.GetObject().(*corev1.Event)
						createdEvent.Name = ""
						createdEvent.Source = corev1.EventSource{}
						createdEvent.FirstTimestamp = metav1.Time{}
						createdEvent.LastTimestamp = metav1.Time{}
						if !cmp.Equal(createdEvent, expectedEvent) {
							return fmt.Errorf("incorrect event reported:\n%s", cmp.Diff(createdEvent, expectedEvent))
						}
						validatedEvent = true
						break
					}
				}
				if !validatedEvent {
					return fmt.Errorf("the requried event was reported, %#v", expectedEvent)
				}
				return nil
			},
			verifyNodeStatus: func(conditions []operatorv1.OperatorCondition) error {
				var expectedCondition operatorv1.OperatorCondition
				expectedCondition.Type = condition.NodeControllerDegradedConditionType
				expectedCondition.Reason = "MasterNodesReady"
				expectedCondition.Status = operatorv1.ConditionFalse
				expectedCondition.Message = "All master nodes are ready"

				return validateNodeControllerDegradedCondition(conditions, expectedCondition)
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(scenario.masterNodes...)
			fakeLister := v1helpers.NewFakeNodeLister(kubeClient)

			var triggerStatusUpdateError func(rv string, spec *operatorv1.StaticPodOperatorStatus) error
			if scenario.triggerStatusApplyError != nil {
				triggerStatusUpdateError = func(rv string, spec *operatorv1.StaticPodOperatorStatus) error {
					return scenario.triggerStatusApplyError
				}
			}
			fakeStaticPodOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
						Conditions:              scenario.existingConditions,
					},
					NodeStatuses: scenario.existingNodeStatuses,
				},
				triggerStatusUpdateError,
				nil,
			)

			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{})

			c := &NodeController{
				operatorClient: fakeStaticPodOperatorClient,
				nodeLister:     fakeLister,
			}
			if err := c.sync(context.TODO(), factory.NewSyncContext("NodeController", eventRecorder)); err != nil {
				t.Fatal(err)
			}

			_, status, _, _ := fakeStaticPodOperatorClient.GetStaticPodOperatorState()
			if err := scenario.verifyNodeStatus(status.OperatorStatus.Conditions); err != nil {
				t.Errorf("%s: failed to verify operator conditions: %v", scenario.name, err)
			}
			if scenario.verifyJSONPatch != nil {
				if err := scenario.verifyJSONPatch(fakeStaticPodOperatorClient.GetPatchedOperatorStatus()); err != nil {
					t.Errorf("%s: failed to verify json patch: %v", scenario.name, err)
				}
			} else if patch := fakeStaticPodOperatorClient.GetPatchedOperatorStatus(); patch != nil {
				t.Errorf("didn't expect JSONPatch but got one: %#v", patch)
			}
			if scenario.verifyKubeClientActions != nil {
				if err := scenario.verifyKubeClientActions(kubeClient.Fake.Actions()); err != nil {
					t.Errorf("failed to veirfy kube client actions: %v", err)
				}
			}
		})
	}
}

func TestNewNodeController(t *testing.T) {
	tests := []struct {
		name               string
		startNodes         []runtime.Object
		startNodeStatus    []operatorv1.NodeStatus
		evaluateNodeStatus func([]operatorv1.NodeStatus) error
	}{
		{
			name:       "single-node",
			startNodes: []runtime.Object{fakeMasterNode("test-node-1")},
			evaluateNodeStatus: func(s []operatorv1.NodeStatus) error {
				if len(s) != 1 {
					return fmt.Errorf("expected 1 node status, got %d", len(s))
				}
				if s[0].NodeName != "test-node-1" {
					return fmt.Errorf("expected 'test-node-1' as node name, got %q", s[0].NodeName)
				}
				return nil
			},
		},
		{
			name:       "multi-node",
			startNodes: []runtime.Object{fakeMasterNode("test-node-1"), fakeMasterNode("test-node-2"), fakeMasterNode("test-node-3")},
			startNodeStatus: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
			},
			evaluateNodeStatus: func(s []operatorv1.NodeStatus) error {
				if len(s) != 3 {
					return fmt.Errorf("expected 3 node status, got %d", len(s))
				}
				if s[0].NodeName != "test-node-1" {
					return fmt.Errorf("expected first node to be test-node-1, got %q", s[0].NodeName)
				}
				if s[1].NodeName != "test-node-2" {
					return fmt.Errorf("expected second node to be test-node-2, got %q", s[1].NodeName)
				}
				return nil
			},
		},
		{
			name:       "single-node-removed",
			startNodes: []runtime.Object{},
			startNodeStatus: []operatorv1.NodeStatus{
				{
					NodeName: "lost-node",
				},
			},
			evaluateNodeStatus: func(s []operatorv1.NodeStatus) error {
				if len(s) != 0 {
					return fmt.Errorf("expected no node status, got %d", len(s))
				}
				return nil
			},
		},
		{
			name:       "no-op",
			startNodes: []runtime.Object{fakeMasterNode("test-node-1")},
			startNodeStatus: []operatorv1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
			},
			evaluateNodeStatus: func(s []operatorv1.NodeStatus) error {
				if len(s) != 1 {
					return fmt.Errorf("expected one node status, got %d", len(s))
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(test.startNodes...)
			fakeLister := v1helpers.NewFakeNodeLister(kubeClient)
			fakeStaticPodOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
					NodeStatuses: test.startNodeStatus,
				},
				nil,
				nil,
			)

			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{})

			c := &NodeController{
				operatorClient: fakeStaticPodOperatorClient,
				nodeLister:     fakeLister,
			}
			// override the lister so we don't have to run the informer to list nodes
			c.nodeLister = fakeLister
			if err := c.sync(context.TODO(), factory.NewSyncContext("NodeController", eventRecorder)); err != nil {
				t.Fatal(err)
			}

			_, status, _, _ := fakeStaticPodOperatorClient.GetStaticPodOperatorState()

			if err := test.evaluateNodeStatus(status.NodeStatuses); err != nil {
				t.Errorf("%s: failed to evaluate node status: %v", test.name, err)
			}
		})

	}
}
