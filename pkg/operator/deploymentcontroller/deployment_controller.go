package deploymentcontroller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/management"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
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
// <name>Degraded: produced when the sync() method returns an error.
type DeploymentController struct {
	name              string
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
	name string,
	manifest []byte,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	deployInformer appsinformersv1.DeploymentInformer,
) *DeploymentController {
	return &DeploymentController{
		name:           name,
		manifest:       manifest,
		operatorClient: operatorClient,
		kubeClient:     kubeClient,
		deployInformer: deployInformer,
		recorder:       recorder,
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
	controller := factory.New().WithInformers(
		informers...,
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	)
	if slices.Contains(c.conditions, opv1.OperatorStatusTypeDegraded) {
		controller = controller.WithSyncDegradedOnError(c.operatorClient)
	}
	return controller.ToController(
		c.name,
		c.recorder.WithComponentSuffix(strings.ToLower(c.name)+"-deployment-controller-"),
	), errors.NewAggregate(c.errors)
}

// Name returns the name of the DeploymentController.
func (c *DeploymentController) Name() string {
	return c.name
}

func (c *DeploymentController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) && management.IsOperatorRemovable() {
		return nil
	}
	if err != nil {
		return err
	}

	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	meta, err := c.operatorClient.GetObjectMeta()
	if err != nil {
		return err
	}
	if management.IsOperatorRemovable() && meta.DeletionTimestamp != nil {
		return c.syncDeleting(ctx, opSpec, opStatus, syncContext)
	}
	return c.syncManaged(ctx, opSpec, opStatus, syncContext)
}

func (c *DeploymentController) syncManaged(ctx context.Context, opSpec *opv1.OperatorSpec, opStatus *opv1.OperatorStatus, syncContext factory.SyncContext) error {
	klog.V(4).Infof("syncManaged")

	if management.IsOperatorRemovable() {
		if err := v1helpers.EnsureFinalizer(ctx, c.operatorClient, c.name); err != nil {
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

	updateStatusFuncs := []v1helpers.UpdateStatusFunc{
		func(newStatus *opv1.OperatorStatus) error {
			// TODO: set ObservedGeneration (the last stable generation change we dealt with)
			resourcemerge.SetDeploymentGeneration(&newStatus.Generations, deployment)
			return nil
		},
	}

	// Set Available Condition
	if slices.Contains(c.conditions, opv1.OperatorStatusTypeAvailable) {
		availableCondition := opv1.OperatorCondition{
			Type:   c.name + opv1.OperatorStatusTypeAvailable,
			Status: opv1.ConditionTrue,
		}
		if deployment.Status.AvailableReplicas > 0 {
			availableCondition.Status = opv1.ConditionTrue
		} else {
			availableCondition.Status = opv1.ConditionFalse
			availableCondition.Message = "Waiting for Deployment"
			availableCondition.Reason = "Deploying"
		}
		updateStatusFuncs = append(updateStatusFuncs, v1helpers.UpdateConditionFn(availableCondition))
	}

	// Set Progressing Condition
	if slices.Contains(c.conditions, opv1.OperatorStatusTypeProgressing) {
		progressingCondition := opv1.OperatorCondition{
			Type:   c.name + opv1.OperatorStatusTypeProgressing,
			Status: opv1.ConditionFalse,
		}
		if ok, msg := isProgressing(deployment); ok {
			progressingCondition.Status = opv1.ConditionTrue
			progressingCondition.Message = msg
			progressingCondition.Reason = "Deploying"
		}
		updateStatusFuncs = append(updateStatusFuncs, v1helpers.UpdateConditionFn(progressingCondition))
	}

	_, _, err = v1helpers.UpdateStatus(
		ctx,
		c.operatorClient,
		updateStatusFuncs...,
	)

	return err
}

func (c *DeploymentController) syncDeleting(ctx context.Context, opSpec *opv1.OperatorSpec, opStatus *opv1.OperatorStatus, syncContext factory.SyncContext) error {
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
	return v1helpers.RemoveFinalizer(ctx, c.operatorClient, c.name)
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

func isProgressing(deployment *appsv1.Deployment) (bool, string) {
	var deploymentExpectedReplicas int32
	if deployment.Spec.Replicas != nil {
		deploymentExpectedReplicas = *deployment.Spec.Replicas
	}

	switch {
	case deployment.Generation != deployment.Status.ObservedGeneration:
		return true, "Waiting for Deployment to act on changes"
	case deployment.Status.UnavailableReplicas > 0:
		return true, "Waiting for Deployment to deploy pods"
	case deployment.Status.UpdatedReplicas < deploymentExpectedReplicas:
		return true, "Waiting for Deployment to update pods"
	case deployment.Status.AvailableReplicas < deploymentExpectedReplicas:
		return true, "Waiting for Deployment to deploy pods"
	}
	return false, ""
}
