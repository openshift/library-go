package deploymentcontroller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	opv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	dpm "github.com/openshift/library-go/pkg/apps/deployment"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

// DeploymentHookFunc is a hook function to modify the Deployment.
type DeploymentHookFunc func(*opv1.OperatorSpec, *appsv1.Deployment) error

// ManifestHookFunc is a hook function to modify the manifest in raw format.
// The hook must not modify the original manifest!
type ManifestHookFunc func(*opv1.OperatorSpec, []byte) ([]byte, error)

// DeploymentController is a generic controller that manages a deployment.
//
// This controller supports removable operands, as configured in pkg/operator/management.
//
// This controller optionally produces the following conditions:
// <name>Available: indicates that the deployment controller  was successfully deployed and at least one Deployment replica is available.
// <name>Progressing: indicates that the Deployment is in progress.
// <name>Degraded: true when the deployment has timed out progressing, when failing pods reduce availability (while not mid-rollout), or when sync returns an error.
type DeploymentController struct {
	// instanceName is the name to identify what instance this belongs too: FooDriver for instance
	instanceName string
	// controllerInstanceName is the name to identify this instance of this particular control loop: FooDriver-CSIDriverNodeService for instance.
	controllerInstanceName string

	manifest          []byte
	operatorClient    v1helpers.OperatorClientWithFinalizers
	kubeClient        kubernetes.Interface
	deployInformer    appsinformersv1.DeploymentInformer
	optionalInformers []factory.Informer
	recorder          events.Recorder
	conditions        []string
	// Optional hook functions to modify the deployment manifest.
	// This helps in modifying the manifests before it deployment
	// is created from the manifest.
	// If one of these functions returns an error, the sync
	// fails indicating the ordinal position of the failed function.
	// Also, in that scenario the Degraded status is set to True.
	// TODO: Collapse this into optional deployment hook.
	optionalManifestHooks []ManifestHookFunc
	// Optional hook functions to modify the Deployment.
	// If one of these functions returns an error, the sync
	// fails indicating the ordinal position of the failed function.
	// Also, in that scenario the Degraded status is set to True.
	optionalDeploymentHooks []DeploymentHookFunc
	// errors contains any errors that occur during the configuration
	// and setup of the DeploymentController.
	errors []error
}

// NewDeploymentController creates a new instance of DeploymentController,
// returning it as a factory.Controller interface. Under the hood it uses
// the NewDeploymentControllerBuilder to construct the controller.
func NewDeploymentController(
	name string,
	manifest []byte,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	deployInformer appsinformersv1.DeploymentInformer,
	optionalInformers []factory.Informer,
	optionalManifestHooks []ManifestHookFunc,
	optionalDeploymentHooks ...DeploymentHookFunc,
) factory.Controller {
	c := NewDeploymentControllerBuilder(
		name,
		manifest,
		recorder,
		operatorClient,
		kubeClient,
		deployInformer,
	).WithConditions(
		opv1.OperatorStatusTypeAvailable,
		opv1.OperatorStatusTypeProgressing,
		opv1.OperatorStatusTypeDegraded,
	).WithExtraInformers(
		optionalInformers...,
	).WithManifestHooks(
		optionalManifestHooks...,
	).WithDeploymentHooks(
		optionalDeploymentHooks...,
	)

	controller, err := c.ToController()
	if err != nil {
		panic(err)
	}
	return controller
}

// NewDeploymentControllerBuilder initializes and returns a pointer to a
// minimal DeploymentController.
func NewDeploymentControllerBuilder(
	instanceName string,
	manifest []byte,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	deployInformer appsinformersv1.DeploymentInformer,
) *DeploymentController {
	return &DeploymentController{
		instanceName:           instanceName,
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "Deployment"),
		manifest:               manifest,
		operatorClient:         operatorClient,
		kubeClient:             kubeClient,
		deployInformer:         deployInformer,
		recorder:               recorder,
	}
}

// WithExtraInformers appends additional informers to the DeploymentController.
// These informers are used to watch for additional resources that might affect the Deployment's state.
func (c *DeploymentController) WithExtraInformers(informers ...factory.Informer) *DeploymentController {
	c.optionalInformers = informers
	return c
}

// WithManifestHooks adds custom hook functions that are called during the handling of the Deployment manifest.
// These hooks can manipulate the manifest or perform specific checks before its convertion into a Deployment object.
func (c *DeploymentController) WithManifestHooks(hooks ...ManifestHookFunc) *DeploymentController {
	c.optionalManifestHooks = hooks
	return c
}

// WithDeploymentHooks adds custom hook functions that are called during the sync.
// These hooks can perform operations or modifications at specific points in the Deployment.
func (c *DeploymentController) WithDeploymentHooks(hooks ...DeploymentHookFunc) *DeploymentController {
	c.optionalDeploymentHooks = hooks
	return c
}

// WithConditions sets the operational conditions under which the DeploymentController will operate.
// Only 'Available', 'Progressing' and 'Degraded' are valid conditions; other values are ignored.
func (c *DeploymentController) WithConditions(conditions ...string) *DeploymentController {
	validConditions := sets.New[string]()
	validConditions.Insert(
		opv1.OperatorStatusTypeAvailable,
		opv1.OperatorStatusTypeProgressing,
		opv1.OperatorStatusTypeDegraded,
	)
	for _, condition := range conditions {
		if validConditions.Has(condition) {
			if !slices.Contains(c.conditions, condition) {
				c.conditions = append(c.conditions, condition)
			}
		} else {
			err := fmt.Errorf("invalid condition %q. Valid conditions include %v", condition, validConditions.UnsortedList())
			c.errors = append(c.errors, err)
		}
	}
	return c
}

// ToController converts the DeploymentController into a factory.Controller.
// It aggregates and returns all errors reported during the builder phase.
func (c *DeploymentController) ToController() (factory.Controller, error) {
	informers := append(
		c.optionalInformers,
		c.operatorClient.Informer(),
		c.deployInformer.Informer(),
	)
	controller := factory.New().WithControllerInstanceName(c.controllerInstanceName).WithInformers(
		informers...,
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	)
	// When this controller owns <name>Degraded in status, do not use WithSyncDegradedOnError: reconcile would set
	// Degraded=False on every successful sync and clear deployment operand degradation (see openshift/library-go#2128).
	if !slices.Contains(c.conditions, opv1.OperatorStatusTypeDegraded) {
		controller = controller.WithSyncDegradedOnError(c.operatorClient)
	}
	return controller.ToController(
		c.instanceName, // don't change what is passed here unless you also remove the old FooDegraded condition
		c.recorder.WithComponentSuffix(strings.ToLower(c.instanceName)+"-deployment-controller-"),
	), errors.NewAggregate(c.errors)
}

// Name returns the name of the DeploymentController.
func (c *DeploymentController) Name() string {
	return c.instanceName
}

func (c *DeploymentController) sync(ctx context.Context, syncContext factory.SyncContext) (err error) {
	if slices.Contains(c.conditions, opv1.OperatorStatusTypeDegraded) {
		defer func() {
			if err != nil {
				applyErr := c.applySyncErrorDegraded(ctx, err)
				if applyErr != nil {
					klog.V(2).Infof("failed to apply sync error degraded status: %v", applyErr)
				}
			}
		}()
	}

	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) && management.IsOperatorRemovable() {
		return nil
	}
	if err != nil {
		return err
	}

	if opSpec.ManagementState == opv1.Removed && management.IsOperatorRemovable() {
		return c.syncDeleting(ctx, opSpec, syncContext)
	}

	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	meta, err := c.operatorClient.GetObjectMeta()
	if err != nil {
		return err
	}
	if management.IsOperatorRemovable() && meta.DeletionTimestamp != nil {
		return c.syncDeleting(ctx, opSpec, syncContext)
	}
	return c.syncManaged(ctx, opSpec, opStatus, syncContext)
}

func (c *DeploymentController) applySyncErrorDegraded(ctx context.Context, syncErr error) error {
	degraded := applyoperatorv1.OperatorCondition().
		WithType(c.instanceName + opv1.OperatorStatusTypeDegraded).
		WithStatus(opv1.ConditionTrue).
		WithReason("SyncError").
		WithMessage(syncErr.Error())
	status := applyoperatorv1.OperatorStatus().WithConditions(degraded)
	return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status)
}

func (c *DeploymentController) syncManaged(ctx context.Context, opSpec *opv1.OperatorSpec, opStatus *opv1.OperatorStatus, syncContext factory.SyncContext) error {
	klog.V(4).Infof("syncManaged")

	if management.IsOperatorRemovable() {
		if err := v1helpers.EnsureFinalizer(ctx, c.operatorClient, c.instanceName); err != nil {
			return err
		}
	}
	required, err := c.getDeployment(opSpec)
	if err != nil {
		return err
	}

	deployment, _, err := resourceapply.ApplyDeployment(
		ctx,
		c.kubeClient.AppsV1(),
		syncContext.Recorder(),
		required,
		resourcemerge.ExpectedDeploymentGeneration(required, opStatus.Generations),
	)
	if err != nil {
		return err
	}

	status := applyoperatorv1.OperatorStatus().
		WithGenerations(&applyoperatorv1.GenerationStatusApplyConfiguration{
			Group:          ptr.To("apps"),
			Resource:       ptr.To("deployments"),
			Namespace:      ptr.To(deployment.Namespace),
			Name:           ptr.To(deployment.Name),
			LastGeneration: ptr.To(deployment.Generation),
		})

	now := time.Now()

	if slices.Contains(c.conditions, opv1.OperatorStatusTypeAvailable) {
		availableCondition := applyoperatorv1.
			OperatorCondition().WithType(c.instanceName + opv1.OperatorStatusTypeAvailable)
		if deployment.Status.AvailableReplicas > 0 {
			availableCondition = availableCondition.
				WithStatus(opv1.ConditionTrue).
				WithMessage("Deployment is available").
				WithReason("AsExpected")
		} else {
			availableCondition = availableCondition.
				WithStatus(opv1.ConditionFalse).
				WithReason("NoPod").
				WithMessage(fmt.Sprintf("no %s.%s pods available on any node", deployment.Name, deployment.Namespace))
		}
		status = status.WithConditions(availableCondition)
	}

	desiredReplicas := ptr.Deref(deployment.Spec.Replicas, 1)

	progressTimedOutMessage, workloadIsBeingUpdatedTooLong := hasDeploymentTimedOutProgressing(deployment.Status)
	workloadIsBeingUpdated := !hasDeploymentProgressed(deployment.Status) && !workloadIsBeingUpdatedTooLong

	var progressDeadlineExceededMessage string
	if workloadIsBeingUpdatedTooLong {
		progressDeadlineExceededMessage = fmt.Sprintf("deployment/%s.%s has timed out progressing: %s", deployment.Name, deployment.Namespace, progressTimedOutMessage)
	}

	if slices.Contains(c.conditions, opv1.OperatorStatusTypeProgressing) {
		progressingCondition := applyoperatorv1.OperatorCondition().
			WithType(c.instanceName + opv1.OperatorStatusTypeProgressing).
			WithStatus(opv1.ConditionFalse).
			WithMessage("Deployment is not progressing").
			WithReason("AsExpected")

		switch {
		case workloadIsBeingUpdated:
			progressingCondition = progressingCondition.
				WithStatus(opv1.ConditionTrue).
				WithReason("PodsUpdating").
				WithMessage(fmt.Sprintf("deployment/%s.%s: %d/%d pods have been updated to the latest revision and %d/%d pods are available", deployment.Name, deployment.Namespace, deployment.Status.UpdatedReplicas, desiredReplicas, deployment.Status.AvailableReplicas, desiredReplicas))
		case workloadIsBeingUpdatedTooLong:
			progressingCondition = progressingCondition.
				WithStatus(opv1.ConditionFalse).
				WithReason("ProgressDeadlineExceeded").
				WithMessage(progressDeadlineExceededMessage)
		default:
			progressingCondition = progressingCondition.
				WithStatus(opv1.ConditionFalse).
				WithReason("AsExpected")
		}
		status = status.WithConditions(progressingCondition)
	}

	if slices.Contains(c.conditions, opv1.OperatorStatusTypeDegraded) {
		degradedCondition := applyoperatorv1.OperatorCondition().
			WithType(c.instanceName + opv1.OperatorStatusTypeDegraded).
			WithStatus(opv1.ConditionFalse).
			WithReason("AsExpected")

		switch {
		case workloadIsBeingUpdatedTooLong:
			degradedCondition = degradedCondition.
				WithStatus(opv1.ConditionTrue).
				WithReason("ProgressDeadlineExceeded").
				WithMessage(progressDeadlineExceededMessage)

		case !workloadIsBeingUpdated && deployment.Status.AvailableReplicas < desiredReplicas:
			operandPods := c.listOperandPodsForDiagnostics(ctx, deployment, syncContext)
			livePods := nonDeletingPods(operandPods)
			hasFailing := hasFailingPods(deployment, livePods, now)
			if hasFailing || deployment.Status.AvailableReplicas == 0 {
				containerMessages := dpm.ContainerMessagesForPods(deployment, livePods)
				var failureDescription string
				if len(containerMessages) > 0 {
					failureDescription = ` (` + strings.Join(containerMessages, ", ") + `)`
				}
				numUnavailable := desiredReplicas - deployment.Status.AvailableReplicas
				message := fmt.Sprintf("%d of %d requested instances are unavailable for %s.%s%s", numUnavailable, desiredReplicas, deployment.Name, deployment.Namespace, failureDescription)
				degradedCondition = degradedCondition.
					WithStatus(opv1.ConditionTrue).
					WithReason("UnavailablePod").
					WithMessage(message)
			} else {
				degradedCondition = degradedCondition.
					WithStatus(opv1.ConditionFalse).
					WithReason("AsExpected")
			}

		default:
			degradedCondition = degradedCondition.
				WithStatus(opv1.ConditionFalse).
				WithReason("AsExpected")
		}
		status = status.WithConditions(degradedCondition)
	}

	return c.operatorClient.ApplyOperatorStatus(
		ctx,
		c.controllerInstanceName,
		status,
	)
}

// listOperandPodsForDiagnostics lists pods matched by the deployment selector for UnavailablePod diagnostics.
// A nil selector, selector conversion errors, or API list errors are logged and recorded as warnings; no error is returned.
func (c *DeploymentController) listOperandPodsForDiagnostics(ctx context.Context, deploymentObj *appsv1.Deployment, syncContext factory.SyncContext) []*corev1.Pod {
	if deploymentObj.Spec.Selector == nil {
		klog.Warningf("deployment/%s/%s has no spec.selector, skipping pod diagnostics", deploymentObj.Namespace, deploymentObj.Name)
		syncContext.Recorder().Warningf("DeploymentSelectorMissing", "deployment %s/%s has no spec.selector, skipping pod diagnostics", deploymentObj.Namespace, deploymentObj.Name)
		return nil
	}
	selector, err := metav1.LabelSelectorAsSelector(deploymentObj.Spec.Selector)
	if err != nil {
		klog.Warningf("deployment/%s/%s has invalid spec.selector: %v", deploymentObj.Namespace, deploymentObj.Name, err)
		syncContext.Recorder().Warningf("DeploymentSelectorInvalid", "deployment %s/%s has invalid spec.selector: %v", deploymentObj.Namespace, deploymentObj.Name, err)
		return nil
	}
	podList, err := c.kubeClient.CoreV1().Pods(deploymentObj.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		klog.Warningf("deployment/%s/%s: pod list for diagnostics failed: %v", deploymentObj.Namespace, deploymentObj.Name, err)
		syncContext.Recorder().Warningf("PodListFailed", "listing pods for deployment %s/%s diagnostics: %v", deploymentObj.Namespace, deploymentObj.Name, err)
		return nil
	}
	out := make([]*corev1.Pod, len(podList.Items))
	for i := range podList.Items {
		out[i] = &podList.Items[i]
	}
	return out
}

func (c *DeploymentController) syncDeleting(ctx context.Context, opSpec *opv1.OperatorSpec, syncContext factory.SyncContext) error {
	klog.V(4).Infof("syncDeleting")
	required, err := c.getDeployment(opSpec)
	if err != nil {
		return err
	}

	err = c.kubeClient.AppsV1().Deployments(required.Namespace).Delete(ctx, required.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	} else {
		klog.V(2).Infof("Deleted Deployment %s/%s", required.Namespace, required.Name)
	}

	// All removed, remove the finalizer as the last step
	return v1helpers.RemoveFinalizer(ctx, c.operatorClient, c.instanceName)
}

func (c *DeploymentController) getDeployment(opSpec *opv1.OperatorSpec) (*appsv1.Deployment, error) {
	manifest := c.manifest
	for i := range c.optionalManifestHooks {
		var err error
		manifest, err = c.optionalManifestHooks[i](opSpec, manifest)
		if err != nil {
			return nil, fmt.Errorf("error running hook function (index=%d): %w", i, err)
		}
	}

	required := resourceread.ReadDeploymentV1OrDie(manifest)

	for i := range c.optionalDeploymentHooks {
		err := c.optionalDeploymentHooks[i](opSpec, required)
		if err != nil {
			return nil, fmt.Errorf("error running hook function (index=%d): %w", i, err)
		}
	}
	return required, nil
}

// hasDeploymentProgressed returns true if the deployment reports NewReplicaSetAvailable
// via the DeploymentProgressing condition.
func hasDeploymentProgressed(status appsv1.DeploymentStatus) bool {
	for _, cond := range status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Status == corev1.ConditionTrue && cond.Reason == "NewReplicaSetAvailable"
		}
	}
	return false
}

// hasDeploymentTimedOutProgressing returns true if the deployment reports ProgressDeadlineExceeded.
// The function returns the Progressing condition message as the first return value.
func hasDeploymentTimedOutProgressing(status appsv1.DeploymentStatus) (string, bool) {
	for _, cond := range status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Message, cond.Status == corev1.ConditionFalse && cond.Reason == "ProgressDeadlineExceeded"
		}
	}
	return "", false
}

// nonDeletingPods returns pods that are not terminating (no deletion timestamp).
func nonDeletingPods(pods []*corev1.Pod) []*corev1.Pod {
	out := make([]*corev1.Pod, 0, len(pods))
	for _, p := range pods {
		if p != nil && p.DeletionTimestamp == nil {
			out = append(out, p)
		}
	}
	return out
}

func hasFailingPods(workload *appsv1.Deployment, pods []*corev1.Pod, now time.Time) bool {
	progressDeadline := time.Duration(ptr.Deref(workload.Spec.ProgressDeadlineSeconds, 600)) * time.Second
	minReady := time.Duration(workload.Spec.MinReadySeconds) * time.Second

	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}

		readyCond := findPodReadyCondition(pod)
		deadline := pod.CreationTimestamp.Time.Add(progressDeadline)

		if (readyCond == nil || readyCond.Status != corev1.ConditionTrue) && now.After(deadline) {
			return true
		}

		if minReady > 0 && readyCond != nil && readyCond.Status == corev1.ConditionTrue {
			isRelevant := now.After(pod.CreationTimestamp.Time.Add(progressDeadline + minReady))
			if isRelevant && now.Sub(readyCond.LastTransitionTime.Time) < minReady {
				return true
			}
		}
	}
	return false
}

func findPodReadyCondition(pod *corev1.Pod) *corev1.PodCondition {
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1.PodReady {
			return &pod.Status.Conditions[i]
		}
	}
	return nil
}
