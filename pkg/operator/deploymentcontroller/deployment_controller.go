package deploymentcontroller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/management"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
// This controller produces the following conditions:
// <name>Available: indicates that the deployment controller  was successfully deployed and at least one Deployment replica is available.
// <name>Progressing: indicates that the Deployment is in progress.
// <name>Degraded: produced when the sync() method returns an error.
type DeploymentController struct {
	name           string
	manifest       []byte
	operatorClient v1helpers.OperatorClientWithFinalizers
	kubeClient     kubernetes.Interface
	deployInformer appsinformersv1.DeploymentInformer
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
}

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
	c := &DeploymentController{
		name:                    name,
		manifest:                manifest,
		operatorClient:          operatorClient,
		kubeClient:              kubeClient,
		deployInformer:          deployInformer,
		optionalManifestHooks:   optionalManifestHooks,
		optionalDeploymentHooks: optionalDeploymentHooks,
	}

	informers := append(
		optionalInformers,
		operatorClient.Informer(),
		deployInformer.Informer(),
	)

	return factory.New().WithInformers(
		informers...,
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).ToController(
		c.name,
		recorder.WithComponentSuffix(strings.ToLower(name)+"-deployment-controller-"),
	)
}

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
		if err := v1helpers.EnsureFinalizer(c.operatorClient, c.name); err != nil {
			return err
		}
	}
	required, err := c.getDeployment(opSpec)
	if err != nil {
		return err
	}

	deployment, _, err := resourceapply.ApplyDeployment(
		context.TODO(),
		c.kubeClient.AppsV1(),
		syncContext.Recorder(),
		required,
		resourcemerge.ExpectedDeploymentGeneration(required, opStatus.Generations),
	)
	if err != nil {
		return err
	}

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

	progressingCondition := opv1.OperatorCondition{
		Type:   c.name + opv1.OperatorStatusTypeProgressing,
		Status: opv1.ConditionFalse,
	}

	if ok, msg := isProgressing(deployment); ok {
		progressingCondition.Status = opv1.ConditionTrue
		progressingCondition.Message = msg
		progressingCondition.Reason = "Deploying"
	}

	updateStatusFn := func(newStatus *opv1.OperatorStatus) error {
		// TODO: set ObservedGeneration (the last stable generation change we dealt with)
		resourcemerge.SetDeploymentGeneration(&newStatus.Generations, deployment)
		return nil
	}

	_, _, err = v1helpers.UpdateStatus(
		c.operatorClient,
		updateStatusFn,
		v1helpers.UpdateConditionFn(availableCondition),
		v1helpers.UpdateConditionFn(progressingCondition),
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
	return v1helpers.RemoveFinalizer(c.operatorClient, c.name)
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
