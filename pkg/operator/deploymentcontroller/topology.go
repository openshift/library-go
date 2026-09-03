package deploymentcontroller

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	opv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// TopologyAwareReplicas returns the desired replica count for a given
// ControlPlaneTopology. For known topologies, the result is deterministic:
//
//   - SingleReplica:          1
//   - DualReplica:            2
//   - HighlyAvailableArbiter: 2
//   - External:               2
//   - HighlyAvailable:        maxReplicas
//
// For unknown topologies, replicas are derived from controlPlaneNodeCount,
// capped at maxReplicas and floored at 1.
func TopologyAwareReplicas(topology configv1.TopologyMode, controlPlaneNodeCount int, maxReplicas int32) int32 {
	switch topology {
	case configv1.SingleReplicaTopologyMode:
		return 1
	case configv1.DualReplicaTopologyMode, configv1.HighlyAvailableArbiterMode, configv1.ExternalTopologyMode:
		return 2
	case configv1.HighlyAvailableTopologyMode:
		return maxReplicas
	default:
		return min(max(int32(controlPlaneNodeCount), 1), maxReplicas)
	}
}

// WithTopologyAwareReplicasHook sets deployment replicas based on the cluster's
// ControlPlaneTopology. See TopologyAwareReplicas for the mapping.
func WithTopologyAwareReplicasHook(
	infrastructureLister configv1listers.InfrastructureLister,
	nodeLister corev1listers.NodeLister,
	maxReplicas int32,
) DeploymentHookFunc {
	cpSelector, err := labels.Parse("node-role.kubernetes.io/control-plane")
	if err != nil {
		panic(err)
	}
	return func(_ *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		infra, err := infrastructureLister.Get("cluster")
		if err != nil {
			return fmt.Errorf("failed to get infrastructure resource: %w", err)
		}
		nodes, err := nodeLister.List(cpSelector)
		if err != nil {
			return err
		}
		replicas := TopologyAwareReplicas(infra.Status.ControlPlaneTopology, len(nodes), maxReplicas)
		deployment.Spec.Replicas = &replicas
		return nil
	}
}

// SetTopologyAwareScheduling configures replicas, anti-affinity, rolling
// update strategy, and control-plane node selector on a Deployment based on
// the cluster's ControlPlaneTopology. It applies all topology adjustments in
// the correct order and can be called directly by operators that do not use
// DeploymentController (e.g. workload.Delegate implementations).
func SetTopologyAwareScheduling(deployment *appsv1.Deployment, topology configv1.TopologyMode, controlPlaneNodeCount int, appLabelValue string, maxSurge, maxReplicas int32) {
	replicas := TopologyAwareReplicas(topology, controlPlaneNodeCount, maxReplicas)
	deployment.Spec.Replicas = &replicas
	setControlPlaneNodeSelector(deployment, topology)
	setSchedulingStrategy(deployment, appLabelValue, maxSurge)
}

// WithTopologyAwareSchedulingHooks returns all three topology-aware deployment
// hooks in the required registration order: replicas, then node selector, then
// scheduling strategy. The returned slice can be spread into
// DeploymentController.WithDeploymentHooks.
func WithTopologyAwareSchedulingHooks(
	infrastructureLister configv1listers.InfrastructureLister,
	nodeLister corev1listers.NodeLister,
	appLabelValue string,
	maxSurge, maxReplicas int32,
) []DeploymentHookFunc {
	return []DeploymentHookFunc{
		WithTopologyAwareReplicasHook(infrastructureLister, nodeLister, maxReplicas),
		WithControlPlaneNodeSelectorHook(infrastructureLister),
		WithTopologyAwareSchedulingHook(appLabelValue, maxSurge),
	}
}

// WithTopologyAwareSchedulingHook sets the rolling update strategy and pod
// anti-affinity based on the deployment's current replica count. It must be
// registered AFTER WithTopologyAwareReplicasHook in the hook chain so that
// replicas are already set.
//
// When replicas > 1, it sets required pod anti-affinity on
// kubernetes.io/hostname using the provided appLabelValue as the selector
// match for the "app" label, and configures maxUnavailable = max(replicas-1, 1)
// with maxSurge set to the provided value.
//
// When replicas == 1 (e.g. SNO), it removes anti-affinity and sets
// maxUnavailable = 1, maxSurge = 1.
func WithTopologyAwareSchedulingHook(appLabelValue string, maxSurge int32) DeploymentHookFunc {
	return func(_ *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		setSchedulingStrategy(deployment, appLabelValue, maxSurge)
		return nil
	}
}

// WithControlPlaneNodeSelectorHook adds a control-plane node selector to the
// deployment, except on External topology (HyperShift) where no control-plane
// nodes exist in-cluster and the selector would leave pods Pending.
func WithControlPlaneNodeSelectorHook(infrastructureLister configv1listers.InfrastructureLister) DeploymentHookFunc {
	return func(_ *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		infra, err := infrastructureLister.Get("cluster")
		if err != nil {
			return fmt.Errorf("failed to get infrastructure resource: %w", err)
		}
		setControlPlaneNodeSelector(deployment, infra.Status.ControlPlaneTopology)
		return nil
	}
}

func setSchedulingStrategy(deployment *appsv1.Deployment, appLabelValue string, maxSurge int32) {
	replicas := int32(1)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}

	maxUnavailable := intstr.FromInt32(max(replicas-1, 1))
	surge := intstr.FromInt32(maxSurge)
	if deployment.Spec.Strategy.RollingUpdate == nil {
		deployment.Spec.Strategy.RollingUpdate = &appsv1.RollingUpdateDeployment{}
	}
	deployment.Spec.Strategy.RollingUpdate.MaxUnavailable = &maxUnavailable
	deployment.Spec.Strategy.RollingUpdate.MaxSurge = &surge

	affinity := deployment.Spec.Template.Spec.Affinity
	if replicas > 1 {
		if affinity == nil {
			affinity = &corev1.Affinity{}
		}
		affinity.PodAntiAffinity = &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					TopologyKey: "kubernetes.io/hostname",
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{appLabelValue},
							},
						},
					},
				},
			},
		}
		deployment.Spec.Template.Spec.Affinity = affinity
	} else if affinity != nil {
		affinity.PodAntiAffinity = nil
		if affinity.NodeAffinity == nil && affinity.PodAffinity == nil {
			deployment.Spec.Template.Spec.Affinity = nil
		}
	}
}

func setControlPlaneNodeSelector(deployment *appsv1.Deployment, topology configv1.TopologyMode) {
	if topology == configv1.ExternalTopologyMode {
		if deployment.Spec.Template.Spec.NodeSelector != nil {
			delete(deployment.Spec.Template.Spec.NodeSelector, "node-role.kubernetes.io/control-plane")
			if len(deployment.Spec.Template.Spec.NodeSelector) == 0 {
				deployment.Spec.Template.Spec.NodeSelector = nil
			}
		}
		return
	}
	if deployment.Spec.Template.Spec.NodeSelector == nil {
		deployment.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}
	deployment.Spec.Template.Spec.NodeSelector["node-role.kubernetes.io/control-plane"] = ""
}
