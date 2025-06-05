package workload

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	operatorv1 "github.com/openshift/api/operator/v1"
	openshiftconfigclientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"
	"github.com/openshift/library-go/pkg/apps/deployment"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	workQueueKey = "key"
)

// Delegate captures a set of methods that hold a custom logic
type Delegate interface {
	// Sync a method that will be used for delegation. It should bring the desired workload into operation.
	//
	// It returns a reference to the workload, a bool indicating whether the operator config is at the highest
	// generation, a bool indicating whether the workload references must be removed from the operator status
	// (e.g. in case the workload has been removed), two strings indicating the name & namespace
	// of the workload that must be cleaned up from the operator status (respective to the conditions to be
	// removed) and a list of errors.
	//
	// When a workload is removed (as indicated by the removeWorkload boolean), not only its respective
	// status conditions will removed, but also its generations, and its version string will be
	// set to "". To make sure that the StatusSyncer removes any versions that are equal to the empty
	// string completely, use StatusSyncer.WithEmptyVersionRemoval().
	Sync(ctx context.Context, controllerContext factory.SyncContext) (
		delegateWorkload *appsv1.Deployment,
		operatorConfigAtHighestGeneration bool,
		removeWorkload bool,
		removedWorkloadName string,
		removedWorkloadNamespace string,
		errs []error,
	)

	// PreconditionFulfilled a method that indicates whether all prerequisites are met and we can Sync.
	//
	// missing preconditions will be reported in the operator's status
	// operator will be degraded, not available and not progressing
	// returned errors (if any) will be added to the Message field
	PreconditionFulfilled(ctx context.Context) (bool, error)
}

// Controller is a generic workload controller that deals with Deployment resource.
// Callers must provide a sync function for delegation. It should bring the desired workload into operation.
// The returned state along with errors will be converted into conditions and persisted in the status field.
type Controller struct {
	controllerInstanceName string
	// conditionsPrefix an optional prefix that will be used as operator's condition type field for example APIServerDeploymentDegraded where APIServer indicates the prefix
	conditionsPrefix     string
	operatorNamespace    string
	targetNamespace      string
	targetOperandVersion string
	// operandNamePrefix is used to set the version for an operand via versionRecorder.SetVersion method
	operandNamePrefix string

	podsLister corev1listers.PodLister

	operatorClient               v1helpers.OperatorClient
	kubeClient                   kubernetes.Interface
	openshiftClusterConfigClient openshiftconfigclientv1.ClusterOperatorInterface

	delegate           Delegate
	queue              workqueue.RateLimitingInterface
	versionRecorder    status.VersionGetter
	preRunCachesSynced []cache.InformerSynced
}

// NewController creates a brand new Controller instance.
//
// the "instanceName" param will be used to set conditions in the status field. It will be suffixed with "WorkloadController",
// so it can end up in the condition in the form of "OAuthAPIWorkloadControllerDeploymentAvailable"
//
// the "operatorNamespace" is used to set "version-mapping" in the correct namespace
//
// the "targetNamespace" represent the namespace for the managed resource (DaemonSet)
func NewController(instanceName, operatorNamespace, targetNamespace, targetOperandVersion, operandNamePrefix, conditionsPrefix string,
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	podLister corev1listers.PodLister,
	informers []factory.Informer,
	targetNamespaceInformers []factory.Informer,
	delegate Delegate,
	openshiftClusterConfigClient openshiftconfigclientv1.ClusterOperatorInterface,
	eventRecorder events.Recorder,
	versionRecorder status.VersionGetter,
) factory.Controller {
	controllerRef := &Controller{
		controllerInstanceName:       factory.ControllerInstanceName(instanceName, "Workload"),
		operatorNamespace:            operatorNamespace,
		targetNamespace:              targetNamespace,
		targetOperandVersion:         targetOperandVersion,
		operandNamePrefix:            operandNamePrefix,
		conditionsPrefix:             conditionsPrefix,
		operatorClient:               operatorClient,
		kubeClient:                   kubeClient,
		podsLister:                   podLister,
		delegate:                     delegate,
		openshiftClusterConfigClient: openshiftClusterConfigClient,
		versionRecorder:              versionRecorder,
		queue:                        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any](), instanceName),
	}

	c := factory.New()
	for _, nsi := range targetNamespaceInformers {
		c.WithNamespaceInformer(nsi, targetNamespace)
	}

	return c.WithSync(controllerRef.sync).
		WithControllerInstanceName(controllerRef.controllerInstanceName).
		WithInformers(informers...).
		ToController(
			fmt.Sprintf("%sWorkloadController", controllerRef.controllerInstanceName),
			eventRecorder,
		)
}

func (c *Controller) sync(ctx context.Context, controllerContext factory.SyncContext) error {
	operatorSpec, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	if run, err := c.shouldSync(ctx, operatorSpec, controllerContext.Recorder()); !run {
		return err
	}

	if fulfilled, err := c.delegate.PreconditionFulfilled(ctx); err != nil {
		return c.updateOperatorStatus(ctx, operatorStatus, nil, false, false, false, "", "", []error{err})
	} else if !fulfilled {
		return c.updateOperatorStatus(ctx, operatorStatus, nil, false, false, false, "", "", nil)
	}

	workload, operatorConfigAtHighestGeneration, removeWorkload, removedWorkloadName, removedWorkloadNamespace, errs := c.delegate.Sync(ctx, controllerContext)

	return c.updateOperatorStatus(ctx, operatorStatus, workload, operatorConfigAtHighestGeneration, true, removeWorkload, removedWorkloadName, removedWorkloadNamespace, errs)
}

// shouldSync checks ManagementState to determine if we can run this operator, probably set by a cluster administrator.
func (c *Controller) shouldSync(ctx context.Context, operatorSpec *operatorv1.OperatorSpec, eventsRecorder events.Recorder) (bool, error) {
	switch operatorSpec.ManagementState {
	case operatorv1.Managed:
		return true, nil
	case operatorv1.Unmanaged:
		return false, nil
	case operatorv1.Removed:
		if err := c.kubeClient.CoreV1().Namespaces().Delete(ctx, c.targetNamespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		return false, nil
	default:
		eventsRecorder.Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", operatorSpec.ManagementState)
		return false, nil
	}
}

func (c *Controller) updateOperatorStatus(ctx context.Context,
	previousStatus *operatorv1.OperatorStatus,
	workload *appsv1.Deployment,
	operatorConfigAtHighestGeneration, preconditionsReady, removeWorkload bool,
	removedWorkloadName, removedWorkloadNamespace string,
	errs []error,
) (err error) {

	if errs == nil {
		errs = []error{}
	}

	typeAvailable := fmt.Sprintf("%sDeployment%s", c.conditionsPrefix, operatorv1.OperatorStatusTypeAvailable)
	typeDegraded := fmt.Sprintf("%sDeployment%s", c.conditionsPrefix, operatorv1.OperatorStatusTypeDegraded)
	typeProgressing := fmt.Sprintf("%sDeployment%s", c.conditionsPrefix, operatorv1.OperatorStatusTypeProgressing)
	typeWorkloadDegraded := fmt.Sprintf("%sWorkload%s", c.conditionsPrefix, operatorv1.OperatorStatusTypeDegraded)

	if removeWorkload {
		if len(removedWorkloadName) == 0 || len(removedWorkloadNamespace) == 0 {
			return kerrors.NewAggregate(append(errs, fmt.Errorf("workload marked as removed but no name and/or namespace provided (name=%s, ns=%s)", removedWorkloadName, removedWorkloadNamespace)))
		}

		// the workload has been removed; remove conditions, generations and version
		patch := jsonpatch.Merge(
			v1helpers.RemoveConditionsJSONPatch(previousStatus, []string{typeAvailable, typeDegraded, typeProgressing, typeWorkloadDegraded}),
			v1helpers.RemoveWorkloadGenerationsJSONPatch(previousStatus, removedWorkloadName, removedWorkloadNamespace),
		)

		if !patch.IsEmpty() {
			c.setVersion(removedWorkloadName, "")
			patchErr := c.operatorClient.PatchOperatorStatus(ctx, patch)
			if patchErr != nil {
				errs = append(errs, patchErr)
			}
		}

		return kerrors.NewAggregate(errs)
	}

	deploymentAvailableCondition := applyoperatorv1.OperatorCondition().WithType(typeAvailable)
	deploymentDegradedCondition := applyoperatorv1.OperatorCondition().WithType(typeDegraded)
	deploymentProgressingCondition := applyoperatorv1.OperatorCondition().WithType(typeProgressing)
	workloadDegradedCondition := applyoperatorv1.OperatorCondition().WithType(typeWorkloadDegraded)

	// update workload conditions, generations and version
	statusApplyConfig := applyoperatorv1.OperatorStatus()
	statusApplyConfig = c.updateOperatorStatusConditions(previousStatus, statusApplyConfig, workload, preconditionsReady, deploymentAvailableCondition, deploymentDegradedCondition, deploymentProgressingCondition, workloadDegradedCondition, errs)
	statusApplyConfig = c.updateOperatorStatusGenerationsVersion(statusApplyConfig, workload, operatorConfigAtHighestGeneration, preconditionsReady)

	applyErr := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, statusApplyConfig)
	if applyErr != nil {
		errs = append(errs, applyErr)
	}

	return kerrors.NewAggregate(errs)
}

func (c *Controller) updateOperatorStatusConditions(
	previousStatus *operatorv1.OperatorStatus,
	statusApplyConfig *applyoperatorv1.OperatorStatusApplyConfiguration,
	workload *appsv1.Deployment,
	preconditionsReady bool,
	deploymentAvailableCondition, deploymentDegradedCondition, deploymentProgressingCondition, workloadDegradedCondition *applyoperatorv1.OperatorConditionApplyConfiguration,
	errs []error,
) *applyoperatorv1.OperatorStatusApplyConfiguration {

	defer statusApplyConfig.WithConditions(
		deploymentAvailableCondition,
		deploymentDegradedCondition,
		deploymentProgressingCondition,
		workloadDegradedCondition,
	)

	if !preconditionsReady {
		var message string
		for _, err := range errs {
			message = message + err.Error() + "\n"
		}
		if len(message) == 0 {
			message = "the operator didn't specify what preconditions are missing"
		}

		// we are degraded, not available and we are not progressing

		deploymentDegradedCondition = deploymentDegradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("PreconditionNotFulfilled").
			WithMessage(message)

		deploymentAvailableCondition = deploymentAvailableCondition.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("PreconditionNotFulfilled")

		deploymentProgressingCondition = deploymentProgressingCondition.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("PreconditionNotFulfilled")

		workloadDegradedCondition = workloadDegradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("PreconditionNotFulfilled").
			WithMessage(message)

		return statusApplyConfig
	}

	if len(errs) > 0 {
		message := ""
		for _, err := range errs {
			message = message + err.Error() + "\n"
		}
		workloadDegradedCondition = workloadDegradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("SyncError").
			WithMessage(message)
	} else if workload == nil {
		workloadDegradedCondition = workloadDegradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("NoDeployment").
			WithMessage(fmt.Sprintf("deployment/%s: could not be retrieved", c.targetNamespace))
	} else {
		workloadDegradedCondition = workloadDegradedCondition.
			WithStatus(operatorv1.ConditionFalse)
	}

	if workload == nil {
		message := fmt.Sprintf("deployment/%s: could not be retrieved", c.targetNamespace)
		deploymentAvailableCondition = deploymentAvailableCondition.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("NoDeployment").
			WithMessage(message)

		deploymentProgressingCondition = deploymentProgressingCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("NoDeployment").
			WithMessage(message)

		deploymentDegradedCondition = deploymentDegradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("NoDeployment").
			WithMessage(message)

		return statusApplyConfig
	}

	if workload.Status.AvailableReplicas == 0 {
		deploymentAvailableCondition = deploymentAvailableCondition.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("NoPod").
			WithMessage(fmt.Sprintf("no %s.%s pods available on any node.", workload.Name, c.targetNamespace))
	} else {
		deploymentAvailableCondition = deploymentAvailableCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("AsExpected")
	}

	desiredReplicas := int32(1)
	if workload.Spec.Replicas != nil {
		desiredReplicas = *(workload.Spec.Replicas)
	}

	// If the workload is up to date, then we are no longer progressing
	workloadAtHighestGeneration := workload.ObjectMeta.Generation == workload.Status.ObservedGeneration
	// Update is done when all pods have been updated to the latest revision
	// and the deployment controller has reported NewReplicaSetAvailable
	workloadIsBeingUpdated := !workloadAtHighestGeneration || !hasDeploymentProgressed(workload.Status)
	workloadIsBeingUpdatedTooLong := v1helpers.IsUpdatingTooLong(previousStatus, *deploymentProgressingCondition.Type)
	if !workloadAtHighestGeneration {
		deploymentProgressingCondition = deploymentProgressingCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("NewGeneration").
			WithMessage(fmt.Sprintf("deployment/%s.%s: observed generation is %d, desired generation is %d.", workload.Name, c.targetNamespace, workload.Status.ObservedGeneration, workload.ObjectMeta.Generation))
	} else if workloadIsBeingUpdated {
		deploymentProgressingCondition = deploymentProgressingCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("PodsUpdating").
			WithMessage(fmt.Sprintf("deployment/%s.%s: %d/%d pods have been updated to the latest generation and %d/%d pods are available", workload.Name, c.targetNamespace, workload.Status.UpdatedReplicas, desiredReplicas, workload.Status.AvailableReplicas, desiredReplicas))
	} else {
		// Terminating pods don't account for any of the other status fields but
		// still can exist in a state when they are accepting connections and would
		// contribute to unexpected behavior when we report Progressing=False.
		// The case of too many pods might occur for example if `TerminationGracePeriodSeconds` is set
		//
		// The workload should ensure this does not happen by using for example EnsureAtMostOnePodPerNode
		// so that the old pods terminate before the new ones are started.
		deploymentProgressingCondition = deploymentProgressingCondition.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("AsExpected")
	}

	// During a rollout the default maxSurge (25%) will allow the available
	// replicas to temporarily exceed the desired replica count. If this were
	// to occur, the operator should not report degraded.
	workloadHasAllPodsAvailable := workload.Status.AvailableReplicas >= desiredReplicas
	if !workloadHasAllPodsAvailable && (!workloadIsBeingUpdated || workloadIsBeingUpdatedTooLong) {
		numNonAvailablePods := desiredReplicas - workload.Status.AvailableReplicas
		deploymentDegradedCondition = deploymentDegradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("UnavailablePod")
		podContainersStatus, err := deployment.PodContainersStatus(workload, c.podsLister)
		if err != nil {
			podContainersStatus = []string{fmt.Sprintf("failed to get pod containers details: %v", err)}
		}
		deploymentDegradedCondition = deploymentDegradedCondition.
			WithMessage(fmt.Sprintf("%v of %v requested instances are unavailable for %s.%s (%s)", numNonAvailablePods, desiredReplicas, workload.Name, c.targetNamespace, strings.Join(podContainersStatus, ", ")))
	} else {
		deploymentDegradedCondition = deploymentDegradedCondition.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("AsExpected")
	}

	return statusApplyConfig
}

func (c *Controller) updateOperatorStatusGenerationsVersion(
	statusApplyConfig *applyoperatorv1.OperatorStatusApplyConfiguration,
	workload *appsv1.Deployment,
	operatorConfigAtHighestGeneration, preconditionsReady bool,
) *applyoperatorv1.OperatorStatusApplyConfiguration {

	if workload == nil {
		return statusApplyConfig
	}

	statusApplyConfig = statusApplyConfig.WithGenerations(applyoperatorv1.GenerationStatus().
		WithGroup("apps").
		WithResource("deployments").
		WithNamespace(workload.Namespace).
		WithName(workload.Name).
		WithLastGeneration(workload.Generation),
	)

	if !preconditionsReady {
		return statusApplyConfig
	}

	desiredReplicas := int32(1)
	if workload.Spec.Replicas != nil {
		desiredReplicas = *(workload.Spec.Replicas)
	}

	workloadAtHighestGeneration := workload.ObjectMeta.Generation == workload.Status.ObservedGeneration
	workloadHasAllPodsAvailable := workload.Status.AvailableReplicas >= desiredReplicas

	// if the deployment is all available and at the expected generation, then update the version to the latest
	// when we update, the image pull spec should immediately be different, which should immediately cause a deployment rollout
	// which should immediately result in a deployment generation diff, which should cause this block to be skipped until it is ready.
	workloadHasAllPodsUpdated := workload.Status.UpdatedReplicas == desiredReplicas
	if workloadAtHighestGeneration && workloadHasAllPodsAvailable && workloadHasAllPodsUpdated && operatorConfigAtHighestGeneration {
		c.setVersion(workload.Name, c.targetOperandVersion)
	}

	return statusApplyConfig
}

func (c *Controller) setVersion(operandName, version string) {
	if len(c.operandNamePrefix) > 0 {
		operandName = fmt.Sprintf("%s-%s", c.operandNamePrefix, operandName)
	}
	c.versionRecorder.SetVersion(operandName, version)
}

// hasDeploymentProgressed returns true if the deployment reports NewReplicaSetAvailable
// via the DeploymentProgressing condition
func hasDeploymentProgressed(status appsv1.DeploymentStatus) bool {
	for _, cond := range status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Status == corev1.ConditionTrue && cond.Reason == "NewReplicaSetAvailable"
		}
	}
	return false
}

// EnsureAtMostOnePodPerNode updates the deployment spec to prevent more than
// one pod of a given replicaset from landing on a node. It accomplishes this
// by adding a label on the template and updates the pod anti-affinity term to include that label.
func EnsureAtMostOnePodPerNode(spec *appsv1.DeploymentSpec, component string) error {
	if len(component) == 0 {
		return errors.New("please specify the component name")
	}

	antiAffinityKey := fmt.Sprintf("%s-anti-affinity", component)
	antiAffinityValue := "true"

	// Label the pod template with the template hash
	spec.Template.Labels[antiAffinityKey] = antiAffinityValue

	// Ensure that match labels are defined
	if spec.Selector == nil {
		return fmt.Errorf("deployment is missing spec.selector")
	}
	if len(spec.Selector.MatchLabels) == 0 {
		return fmt.Errorf("deployment is missing spec.selector.matchLabels")
	}

	// Ensure anti-affinity selects on the uuid
	antiAffinityMatchLabels := map[string]string{
		antiAffinityKey: antiAffinityValue,
	}
	// Ensure anti-affinity selects on the same labels as the deployment
	for key, value := range spec.Selector.MatchLabels {
		antiAffinityMatchLabels[key] = value
	}

	// Add an anti-affinity rule to the pod template that precludes more than
	// one pod for a uuid from being scheduled to a node.
	spec.Template.Spec.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					TopologyKey: "kubernetes.io/hostname",
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: antiAffinityMatchLabels,
					},
				},
			},
		},
	}

	return nil
}

// CountNodesFuncWrapper returns a function that returns the number of nodes that match the given
// selector. This supports determining the number of master nodes to
// allow setting the deployment replica count to match.
func CountNodesFuncWrapper(nodeLister corev1listers.NodeLister) func(nodeSelector map[string]string) (*int32, error) {
	return func(nodeSelector map[string]string) (*int32, error) {
		nodes, err := nodeLister.List(labels.SelectorFromSet(nodeSelector))
		if err != nil {
			return nil, err
		}
		replicas := int32(len(nodes))
		return &replicas, nil
	}
}
