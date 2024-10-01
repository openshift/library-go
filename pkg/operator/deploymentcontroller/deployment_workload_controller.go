package deploymentcontroller

import (
	"context"
	"fmt"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/management"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type MyController struct {
	DeploymentController
	name          string
	preconditions []PreconditionFunc
}

type PreconditionFunc func(context.Context) (bool, error)

func NewWorkloadController(
	name string,
	operandNamespace string,
	manifest []byte,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	deployInformer appsinformersv1.DeploymentInformer,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	preconditions []PreconditionFunc,
	optionalInformers []factory.Informer,
	optionalManifestHooks []ManifestHookFunc,
	optionalDeploymentHooks ...DeploymentHookFunc,
) factory.Controller {
	c := DelegateBuilder(
		manifest,
		recorder,
		operatorClient,
		kubeClient,
		deployInformer,
	).WithPrecondition(
		preconditions,
	).WithManifestHooks(
		optionalManifestHooks...,
	).WithDeploymentHooks(
		optionalDeploymentHooks...,
	)

	workloadController := workload.NewController(
		name,
		operandNamespace,
		operandNamespace,
		status.VersionForOperandFromEnv(),
		"", //Not needed.
		"", //Not needed.
		operatorClient,
		kubeClient,
		kubeInformersForNamespaces.PodLister(),
		optionalInformers,
		[]factory.Informer{kubeInformersForNamespaces.InformersFor(operandNamespace).Core().V1().Namespaces().Informer()},
		c,
		nil, //Not used?
		c.recorder,
		status.NewVersionGetter(),
	)

	return workloadController
}

func DelegateBuilder(
	manifest []byte,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	deployInformer appsinformersv1.DeploymentInformer,
) *MyController {
	return &MyController{
		DeploymentController: DeploymentController{
			manifest:       manifest,
			recorder:       recorder,
			operatorClient: operatorClient,
			kubeClient:     kubeClient,
			deployInformer: deployInformer,
		},
	}
}

func (c *MyController) WithPrecondition(preconditions []PreconditionFunc) *MyController {
	c.preconditions = append(c.preconditions, preconditions...)
	return c
}

func (c *MyController) WithManifestHooks(hooks ...ManifestHookFunc) *MyController {
	c.optionalManifestHooks = hooks
	return c
}

func (c *MyController) WithDeploymentHooks(hooks ...DeploymentHookFunc) *MyController {
	c.optionalDeploymentHooks = hooks
	return c
}

// Name returns the name of the DeploymentController.
func (c *MyController) Name() string {
	return c.name
}

// PreconditionFulfilled is a function that indicates whether all prerequisites are met and we can Sync.
func (c *MyController) PreconditionFulfilled(ctx context.Context) (bool, error) {
	return c.preconditionFulfilledInternal(ctx)
}

func (c *MyController) preconditionFulfilledInternal(ctx context.Context) (bool, error) {
	klog.V(4).Infof("Precondition checks started.")
	var errs []error
	ok := true
	if c.preconditions != nil {
		for _, precondition := range c.preconditions {
			if ok, err := precondition(ctx); err != nil || !ok {
				errs = append(errs, err)
				ok = false
			}
		}
	}
	preconditionErrors := v1helpers.NewMultiLineAggregate(errs)

	return ok, preconditionErrors
}

func (c *MyController) Sync(ctx context.Context, syncContext factory.SyncContext) (*appsv1.Deployment, bool, []error) {
	errors := []error{}

	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) && management.IsOperatorRemovable() {
		return nil, true, errors
	}
	if err != nil {
		errors = append(errors, err)
	}

	meta, err := c.operatorClient.GetObjectMeta()
	if err != nil {
		errors = append(errors, err)
	}

	required, err := c.getDeployment(opSpec)
	if err != nil {
		errors = append(errors, err)
		return nil, true, errors
	}

	// TODO: Reconsider the approach for calculating controller conditions.
	// Currently, conditions are derived from a Deployment loaded from YAML manifests, which may not be ideal.
	// Consider removing Available/Progressing/Degraded conditions from controller and allowing operators to add their own specific conditions as needed.
	var deployment *appsv1.Deployment
	if management.IsOperatorRemovable() && meta.DeletionTimestamp != nil {
		deployment, err = c.syncDeleting(ctx, required)
		if err != nil {
			errors = append(errors, err)
		}
	} else {
		deployment, err = c.syncManaged(ctx, required, opStatus, syncContext)
		if err != nil {
			errors = append(errors, err)
		}
	}

	//TODO: Returning operatorConfigAtHighestGeneration=true always, we don't have status.observedGeneration in operator.
	return deployment, true, errors
}

func (c *MyController) syncManaged(ctx context.Context, required *appsv1.Deployment, opStatus *opv1.OperatorStatus, syncContext factory.SyncContext) (*appsv1.Deployment, error) {
	klog.V(4).Infof("syncManaged")

	if management.IsOperatorRemovable() {
		if err := v1helpers.EnsureFinalizer(ctx, c.operatorClient, c.name); err != nil {
			return nil, err
		}
	}

	deployment, _, err := resourceapply.ApplyDeployment(
		ctx,
		c.kubeClient.AppsV1(),
		syncContext.Recorder(),
		required,
		resourcemerge.ExpectedDeploymentGeneration(required, opStatus.Generations),
	)
	if err != nil {
		return nil, err
	}

	return deployment, err
}

func (c *MyController) syncDeleting(ctx context.Context, required *appsv1.Deployment) (*appsv1.Deployment, error) {
	klog.V(4).Infof("syncDeleting")

	err := c.kubeClient.AppsV1().Deployments(required.Namespace).Delete(ctx, required.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	} else {
		klog.V(2).Infof("Deleted Deployment %s/%s", required.Namespace, required.Name)
	}

	// All removed, remove the finalizer as the last step
	if v1helpers.RemoveFinalizer(ctx, c.operatorClient, c.name); err != nil {
		return nil, err
	}

	return required, nil
}

func (c *MyController) getDeployment(opSpec *opv1.OperatorSpec) (*appsv1.Deployment, error) {
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
