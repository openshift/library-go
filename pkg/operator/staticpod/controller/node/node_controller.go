package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	coreapiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	corelisterv1 "k8s.io/client-go/listers/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// DefaultRebootingNodeDegradedInertia is the default period during which a node rebooting for upgrade is not considered Degraded.
// The value is pretty large because bare metal nodes can take a long time to reboot for upgrade.
const DefaultRebootingNodeDegradedInertia = 2 * time.Hour

const (
	machineConfigDaemonPostConfigAction = "machineconfiguration.openshift.io/post-config-action"

	machineConfigDaemonStateRebooting = "Rebooting"
)

// NodeControllerOption can be passed to NewNodeController to configure the controller.
type NodeControllerOption func(*NodeController)

// SetRebootingNodeDegradedInertia sets the period during which a node rebooting for upgrade is not considered Degraded.
func SetRebootingNodeDegradedInertia(inert time.Duration) NodeControllerOption {
	return func(c *NodeController) {
		c.rebootingNodeDegradedInertia = inert
	}
}

// NodeController watches for new master nodes and adds them to the node status list in the operator config status.
type NodeController struct {
	controllerInstanceName       string
	operatorClient               v1helpers.StaticPodOperatorClient
	nodeLister                   corelisterv1.NodeLister
	extraNodeSelector            labels.Selector
	masterNodesSelector          labels.Selector
	rebootingNodeDegradedInertia time.Duration
}

// NewNodeController creates a new node controller.
func NewNodeController(
	instanceName string,
	operatorClient v1helpers.StaticPodOperatorClient,
	kubeInformersClusterScoped informers.SharedInformerFactory,
	eventRecorder events.Recorder,
	extraNodeSelector labels.Selector,
	options ...NodeControllerOption,
) factory.Controller {
	c := &NodeController{
		controllerInstanceName:       factory.ControllerInstanceName(instanceName, "Node"),
		operatorClient:               operatorClient,
		nodeLister:                   kubeInformersClusterScoped.Core().V1().Nodes().Lister(),
		extraNodeSelector:            extraNodeSelector,
		rebootingNodeDegradedInertia: DefaultRebootingNodeDegradedInertia,
	}
	for _, opt := range options {
		opt(c)
	}

	masterNodesSelector, err := labels.Parse("node-role.kubernetes.io/master=")
	if err != nil {
		panic(err)
	}
	c.masterNodesSelector = masterNodesSelector

	return factory.New().
		WithInformers(
			operatorClient.Informer(),
			kubeInformersClusterScoped.Core().V1().Nodes().Informer(),
		).
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		ToController(
			c.controllerInstanceName,
			eventRecorder,
		)
}

func (c *NodeController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	_, originalOperatorStatus, _, err := c.operatorClient.GetStaticPodOperatorState()
	if err != nil {
		return err
	}

	nodes, err := c.nodeLister.List(c.masterNodesSelector)
	if err != nil {
		return err
	}

	// Due to a design choice on ORing keys in label selectors, we run this query again to allow for additional
	// selectors as well as selectors that want to OR with master nodes.
	// see: https://github.com/kubernetes/kubernetes/issues/90549#issuecomment-620625847
	if c.extraNodeSelector != nil {
		extraNodes, err := c.nodeLister.List(c.extraNodeSelector)
		if err != nil {
			return err
		}
		nodes = append(nodes, extraNodes...)
	}

	jsonPatch := jsonpatch.New()
	var removedNodeStatusesCounter int
	newTargetNodeStates := []*applyoperatorv1.NodeStatusApplyConfiguration{}
	// remove entries for missing nodes
	for i, nodeState := range originalOperatorStatus.NodeStatuses {
		found := false
		for _, node := range nodes {
			if nodeState.NodeName == node.Name {
				found = true
			}
		}
		if found {
			newTargetNodeState := applyoperatorv1.NodeStatus().WithNodeName(originalOperatorStatus.NodeStatuses[i].NodeName)
			newTargetNodeStates = append(newTargetNodeStates, newTargetNodeState)
		} else {
			syncCtx.Recorder().Warningf("MasterNodeRemoved", "Observed removal of master node %s", nodeState.NodeName)
			// each delete operation is applied to the object,
			// which modifies the array. Thus, we need to
			// adjust the indices to find the correct node to remove.
			removeAtIndex := i
			if !jsonPatch.IsEmpty() {
				removeAtIndex = removeAtIndex - removedNodeStatusesCounter
			}
			jsonPatch.WithRemove(fmt.Sprintf("/status/nodeStatuses/%d", removeAtIndex), jsonpatch.NewTestCondition(fmt.Sprintf("/status/nodeStatuses/%d/nodeName", removeAtIndex), nodeState.NodeName))
			removedNodeStatusesCounter++
		}
	}

	// add entries for new nodes
	for _, node := range nodes {
		found := false
		for _, nodeState := range originalOperatorStatus.NodeStatuses {
			if nodeState.NodeName == node.Name {
				found = true
			}
		}
		if found {
			continue
		}

		syncCtx.Recorder().Eventf("MasterNodeObserved", "Observed new master node %s", node.Name)
		newTargetNodeState := applyoperatorv1.NodeStatus().WithNodeName(node.Name)
		newTargetNodeStates = append(newTargetNodeStates, newTargetNodeState)
	}

	degradedCondition := applyoperatorv1.OperatorCondition().WithType(condition.NodeControllerDegradedConditionType)
	if !jsonPatch.IsEmpty() {
		if err = c.operatorClient.PatchStaticOperatorStatus(ctx, jsonPatch); err != nil {
			degradedCondition = degradedCondition.
				WithStatus(operatorv1.ConditionTrue).
				WithReason("MasterNodeNotRemoved").
				WithMessage(fmt.Sprintf("failed applying JSONPatch, err: %v", err.Error()))

			status := applyoperatorv1.StaticPodOperatorStatus().
				WithConditions(degradedCondition).
				WithNodeStatuses(newTargetNodeStates...)

			return c.operatorClient.ApplyStaticPodOperatorStatus(ctx, c.controllerInstanceName, status)
		}
	}

	// Detect and report master nodes that are not ready.
	// Nodes currently rebooting for upgrade do not cause Degraded condition to be set within the inertia period.
	var degradedNodes []string
	var rebootingNodes []string
	for _, node := range nodes {
		nodeReadyCondition := nodeConditionFinder(&node.Status, coreapiv1.NodeReady)

		var degradedMsg string
		switch {
		case nodeReadyCondition == nil:
			// If a "Ready" condition is not found, that node should be deemed as not Ready by default.
			degradedMsg = fmt.Sprintf("node %q not ready, no Ready condition found in status block", node.Name)

		case nodeReadyCondition.Status != coreapiv1.ConditionTrue:
			degradedMsg = fmt.Sprintf("node %q not ready since %s because %s (%s)", node.Name, nodeReadyCondition.LastTransitionTime, nodeReadyCondition.Reason, nodeReadyCondition.Message)
		}
		if len(degradedMsg) > 0 {
			if nodeRebootingForUpgrade(node) && !shouldDegradeRebootingNode(nodeReadyCondition, c.rebootingNodeDegradedInertia) {
				rebootingNodes = append(rebootingNodes, fmt.Sprintf("node %q", node.Name))
			} else {
				degradedNodes = append(degradedNodes, degradedMsg)
			}
		}
	}

	degradedCondition = degradedCondition.WithReason("MasterNodesReady")

	if len(degradedNodes) > 0 {
		degradedCondition = degradedCondition.WithStatus(operatorv1.ConditionTrue)
	} else {
		degradedCondition = degradedCondition.WithStatus(operatorv1.ConditionFalse)
	}

	var msg strings.Builder
	if len(degradedNodes) > 0 {
		msg.WriteString(fmt.Sprintf("The master nodes not ready: %s", strings.Join(degradedNodes, ", ")))
	}
	if len(rebootingNodes) > 0 {
		if msg.Len() > 0 {
			msg.WriteString(". ")
		}
		msg.WriteString(fmt.Sprintf("The master nodes rebooting for upgrade: %s", strings.Join(rebootingNodes, ", ")))
	}
	if msg.Len() > 0 {
		degradedCondition = degradedCondition.WithMessage(msg.String())
	} else {
		degradedCondition = degradedCondition.WithMessage("All master nodes are ready")
	}

	status := applyoperatorv1.StaticPodOperatorStatus().
		WithConditions(degradedCondition).
		WithNodeStatuses(newTargetNodeStates...)

	if err = c.operatorClient.ApplyStaticPodOperatorStatus(ctx, c.controllerInstanceName, status); err != nil {
		return err
	}

	oldNodeDegradedCondition := v1helpers.FindOperatorCondition(originalOperatorStatus.Conditions, condition.NodeControllerDegradedConditionType)
	if oldNodeDegradedCondition == nil || oldNodeDegradedCondition.Message != *degradedCondition.Message {
		syncCtx.Recorder().Eventf("MasterNodesReadyChanged", *degradedCondition.Message)
	}
	return nil
}

func nodeConditionFinder(status *coreapiv1.NodeStatus, condType coreapiv1.NodeConditionType) *coreapiv1.NodeCondition {
	for i := range status.Conditions {
		if status.Conditions[i].Type == condType {
			return &status.Conditions[i]
		}
	}

	return nil
}

func nodeRebootingForUpgrade(node *coreapiv1.Node) bool {
	return node.Annotations[machineConfigDaemonPostConfigAction] == machineConfigDaemonStateRebooting
}

func shouldDegradeRebootingNode(nodeReadyCondition *coreapiv1.NodeCondition, inert time.Duration) bool {
	return nodeReadyCondition == nil || time.Since(nodeReadyCondition.LastTransitionTime.Time) > inert
}
