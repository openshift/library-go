package workload

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	"github.com/openshift/library-go/pkg/apps/deployment"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	workQueueKey = "key"
)

// Delegate captures a set of methods that hold a custom logic
type Delegate interface {
	// Sync a method that will be used for delegation. It should bring the desired workload into operation.
	Sync(ctx context.Context, controllerContext factory.SyncContext) (*appsv1.Deployment, bool, []error)

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
// the "name" param will be used to set conditions in the status field. It will be suffixed with "WorkloadController",
// so it can end up in the condition in the form of "OAuthAPIWorkloadControllerDeploymentAvailable"
//
// the "operatorNamespace" is used to set "version-mapping" in the correct namespace
//
// the "targetNamespace" represent the namespace for the managed resource (DaemonSet)
func NewController(name, operatorNamespace, targetNamespace, targetOperandVersion, operandNamePrefix, conditionsPrefix string,
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	podLister corev1listers.PodLister,
	informers []factory.Informer,
	tagetNamespaceInformers []factory.Informer,
	delegate Delegate,
	openshiftClusterConfigClient openshiftconfigclientv1.ClusterOperatorInterface,
	eventRecorder events.Recorder,
	versionRecorder status.VersionGetter,
) factory.Controller {
	controllerRef := &Controller{
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
		queue:                        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), name),
	}

	c := factory.New()
	for _, nsi := range tagetNamespaceInformers {
		c.WithNamespaceInformer(nsi, targetNamespace)
	}

	return c.WithSync(controllerRef.sync).
		WithInformers(informers...).
		ToController(
			fmt.Sprintf("%sWorkloadController", name), // don't change what is passed here unless you also remove the old FooDegraded condition
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
		return c.updateOperatorStatus(ctx, operatorStatus, nil, false, false, []error{err})
	} else if !fulfilled {
		return c.updateOperatorStatus(ctx, operatorStatus, nil, false, false, nil)
	}

	workload, operatorConfigAtHighestGeneration, errs := c.delegate.Sync(ctx, controllerContext)

	return c.updateOperatorStatus(ctx, operatorStatus, workload, operatorConfigAtHighestGeneration, true, errs)
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

// updateOperatorStatus updates the status based on the actual workload and errors that might have occurred during synchronization.
func (c *Controller) updateOperatorStatus(ctx context.Context, previousStatus *operatorv1.OperatorStatus, workload *appsv1.Deployment, operatorConfigAtHighestGeneration bool, preconditionsReady bool, errs []error) (err error) {
	if errs == nil {
		errs = []error{}
	}

	deploymentAvailableCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDeployment%s", c.conditionsPrefix, operatorv1.OperatorStatusTypeAvailable),
		Status: operatorv1.ConditionTrue,
	}

	workloadDegradedCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sWorkloadDegraded", c.conditionsPrefix),
		Status: operatorv1.ConditionFalse,
	}

	deploymentDegradedCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDeploymentDegraded", c.conditionsPrefix),
		Status: operatorv1.ConditionFalse,
	}

	deploymentProgressingCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDeployment%s", c.conditionsPrefix, operatorv1.OperatorStatusTypeProgressing),
		Status: operatorv1.ConditionFalse,
	}

	// only set updateGenerationFn to update the observed generation if everything is available
	var updateGenerationFn func(newStatus *operatorv1.OperatorStatus) error
	defer func() {
		updates := []v1helpers.UpdateStatusFunc{
			v1helpers.UpdateConditionFn(deploymentAvailableCondition),
			v1helpers.UpdateConditionFn(deploymentDegradedCondition),
			v1helpers.UpdateConditionFn(deploymentProgressingCondition),
			v1helpers.UpdateConditionFn(workloadDegradedCondition),
		}
		if updateGenerationFn != nil {
			updates = append(updates, updateGenerationFn)
		}
		if _, _, updateError := v1helpers.UpdateStatus(ctx, c.operatorClient, updates...); updateError != nil {
			err = updateError
		}
	}()

	if !preconditionsReady {
		var message string
		for _, err := range errs {
			message = message + err.Error() + "\n"
		}
		if len(message) == 0 {
			message = "the operator didn't specify what preconditions are missing"
		}

		// we are degraded, not available and we are not progressing

		deploymentDegradedCondition.Status = operatorv1.ConditionTrue
		deploymentDegradedCondition.Reason = "PreconditionNotFulfilled"
		deploymentDegradedCondition.Message = message

		deploymentAvailableCondition.Status = operatorv1.ConditionFalse
		deploymentAvailableCondition.Reason = "PreconditionNotFulfilled"

		deploymentProgressingCondition.Status = operatorv1.ConditionFalse
		deploymentProgressingCondition.Reason = "PreconditionNotFulfilled"

		return kerrors.NewAggregate(errs)
	}

	if len(errs) > 0 {
		message := ""
		for _, err := range errs {
			message = message + err.Error() + "\n"
		}
		workloadDegradedCondition.Status = operatorv1.ConditionTrue
		workloadDegradedCondition.Reason = "SyncError"
		workloadDegradedCondition.Message = message
	} else {
		workloadDegradedCondition.Status = operatorv1.ConditionFalse
	}

	if workload == nil {
		message := fmt.Sprintf("deployment/%s: could not be retrieved", c.targetNamespace)
		deploymentAvailableCondition.Status = operatorv1.ConditionFalse
		deploymentAvailableCondition.Reason = "NoDeployment"
		deploymentAvailableCondition.Message = message

		deploymentProgressingCondition.Status = operatorv1.ConditionTrue
		deploymentProgressingCondition.Reason = "NoDeployment"
		deploymentProgressingCondition.Message = message

		deploymentDegradedCondition.Status = operatorv1.ConditionTrue
		deploymentDegradedCondition.Reason = "NoDeployment"
		deploymentDegradedCondition.Message = message

		return kerrors.NewAggregate(errs)
	}

	if workload.Status.AvailableReplicas == 0 {
		deploymentAvailableCondition.Status = operatorv1.ConditionFalse
		deploymentAvailableCondition.Reason = "NoPod"
		deploymentAvailableCondition.Message = fmt.Sprintf("no %s.%s pods available on any node.", workload.Name, c.targetNamespace)
	} else {
		deploymentAvailableCondition.Status = operatorv1.ConditionTrue
		deploymentAvailableCondition.Reason = "AsExpected"
	}

	desiredReplicas := int32(1)
	if workload.Spec.Replicas != nil {
		desiredReplicas = *(workload.Spec.Replicas)
	}

	// If the workload is up to date, then we are no longer progressing
	workloadAtHighestGeneration := workload.ObjectMeta.Generation == workload.Status.ObservedGeneration
	workloadIsBeingUpdated := workload.Status.UpdatedReplicas < desiredReplicas
	workloadIsBeingUpdatedTooLong, err := isUpdatingTooLong(previousStatus, deploymentProgressingCondition.Type)
	if !workloadAtHighestGeneration {
		deploymentProgressingCondition.Status = operatorv1.ConditionTrue
		deploymentProgressingCondition.Reason = "NewGeneration"
		deploymentProgressingCondition.Message = fmt.Sprintf("deployment/%s.%s: observed generation is %d, desired generation is %d.", workload.Name, c.targetNamespace, workload.Status.ObservedGeneration, workload.ObjectMeta.Generation)
	} else if workloadIsBeingUpdated {
		deploymentProgressingCondition.Status = operatorv1.ConditionTrue
		deploymentProgressingCondition.Reason = "PodsUpdating"
		deploymentProgressingCondition.Message = fmt.Sprintf("deployment/%s.%s: %d/%d pods have been updated to the latest generation", workload.Name, c.targetNamespace, workload.Status.UpdatedReplicas, desiredReplicas)
	} else {
		deploymentProgressingCondition.Status = operatorv1.ConditionFalse
		deploymentProgressingCondition.Reason = "AsExpected"
	}

	// During a rollout the default maxSurge (25%) will allow the available
	// replicas to temporarily exceed the desired replica count. If this were
	// to occur, the operator should not report degraded.
	workloadHasAllPodsAvailable := workload.Status.AvailableReplicas >= desiredReplicas
	if !workloadHasAllPodsAvailable && (!workloadIsBeingUpdated || workloadIsBeingUpdatedTooLong) {
		numNonAvailablePods := desiredReplicas - workload.Status.AvailableReplicas
		deploymentDegradedCondition.Status = operatorv1.ConditionTrue
		deploymentDegradedCondition.Reason = "UnavailablePod"
		podContainersStatus, err := deployment.PodContainersStatus(workload, c.podsLister)
		if err != nil {
			podContainersStatus = []string{fmt.Sprintf("failed to get pod containers details: %v", err)}
		}
		deploymentDegradedCondition.Message = fmt.Sprintf("%v of %v requested instances are unavailable for %s.%s (%s)", numNonAvailablePods, desiredReplicas, workload.Name, c.targetNamespace,
			strings.Join(podContainersStatus, ", "))
	} else {
		deploymentDegradedCondition.Status = operatorv1.ConditionFalse
		deploymentDegradedCondition.Reason = "AsExpected"
	}

	// if the deployment is all available and at the expected generation, then update the version to the latest
	// when we update, the image pull spec should immediately be different, which should immediately cause a deployment rollout
	// which should immediately result in a deployment generation diff, which should cause this block to be skipped until it is ready.
	workloadHasAllPodsUpdated := workload.Status.UpdatedReplicas == desiredReplicas
	if workloadAtHighestGeneration && workloadHasAllPodsAvailable && workloadHasAllPodsUpdated && operatorConfigAtHighestGeneration {
		operandName := workload.Name
		if len(c.operandNamePrefix) > 0 {
			operandName = fmt.Sprintf("%s-%s", c.operandNamePrefix, workload.Name)
		}
		c.versionRecorder.SetVersion(operandName, c.targetOperandVersion)
	}

	// set updateGenerationFn so that it is invoked in defer
	updateGenerationFn = func(newStatus *operatorv1.OperatorStatus) error {
		resourcemerge.SetDeploymentGeneration(&newStatus.Generations, workload)
		return nil
	}

	if len(errs) > 0 {
		return kerrors.NewAggregate(errs)
	}
	return nil
}

// isUpdatingTooLong determines if updating operands takes too long.
// it returns true if the progressing condition has been set to True for at least 15 minutes
func isUpdatingTooLong(operatorStatus *operatorv1.OperatorStatus, progressingConditionType string) (bool, error) {
	progressing := v1helpers.FindOperatorCondition(operatorStatus.Conditions, progressingConditionType)
	return progressing != nil && progressing.Status == operatorv1.ConditionTrue && time.Now().After(progressing.LastTransitionTime.Add(15*time.Minute)), nil
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
