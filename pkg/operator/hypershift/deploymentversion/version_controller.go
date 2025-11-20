package deploymentversioncontroller

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	operatorapi "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	defaultReSyncPeriod = 10 * time.Minute

	// This annotation is rendered as soon as the operator publishes Deployment object on API server
	desiredVersionAnnotation = "release.openshift.io/desired-version"

	// This annotation is rendered when the operator verified that the Deployment is up and running
	versionAnnotation = "release.openshift.io/version"
)

// This controller updates versionAnnotation of the Deployment specified by controllerDeploymentName
// with the current version of the operator, read from the "OPERATOR_IMAGE_VERSION" environment variable.
// The controller expects this environment variable to be set to a reasonable value.
// The controller checks whether a rollout of the Deployment with the current version is in progress
// and updates versionAnnotation only when the deployment has completed.
// The controller relies on `.status.conditions` with the `Progressing` type to
// ensure that the deployment has completed, as explained in the Kubernetes docs:
// https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#complete-deployment
// The controller expects the operator to publish the Deployment with desiredVersionAnnotation
// equal to the current version of the operator. The lack of this annotation is treated as an old
// Deployment from some previous version of the operator that did not use this controller.
// Currently, this controller is supposed to be used only for Deployments residing in HyperShift
// control planes.
type DeploymentVersionController struct {
	name                     string
	controlPlaneNamespace    string
	controllerDeploymentName string
	deploymentInformer       appsinformersv1.DeploymentInformer
	operatorClient           v1helpers.OperatorClientWithFinalizers
	controlPlaneKubeClient   kubernetes.Interface
	eventRecorder            events.Recorder
}

func NewDeploymentVersionController(
	name string,
	controlPlaneNamespace string,
	controllerDeploymentName string,
	deploymentInformer appsinformersv1.DeploymentInformer,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	controlPlaneKubeClient kubernetes.Interface,
	eventRecorder events.Recorder) factory.Controller {

	c := &DeploymentVersionController{
		name:                     name,
		controlPlaneNamespace:    controlPlaneNamespace,
		controllerDeploymentName: controllerDeploymentName,
		deploymentInformer:       deploymentInformer,
		operatorClient:           operatorClient,
		controlPlaneKubeClient:   controlPlaneKubeClient,
		eventRecorder:            eventRecorder,
	}
	return factory.New().WithSync(
		c.Sync,
	).WithSyncDegradedOnError(
		operatorClient,
	).WithInformers(
		c.deploymentInformer.Informer(),
	).ResyncEvery(
		defaultReSyncPeriod,
	).ToController(
		name,
		eventRecorder,
	)
}

func hasFinishedProgressing(deployment *appsv1.Deployment) bool {
	if deployment.Status.ObservedGeneration != deployment.Generation {
		// The Deployment controller did not act on the Deployment spec change yet.
		// Any condition in the status may be stale.
		return false
	}
	// Deployment whose rollout is complete gets Progressing condition with Reason NewReplicaSetAvailable condition.
	// https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#complete-deployment
	for _, cond := range deployment.Status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Status == corev1.ConditionTrue && cond.Reason == "NewReplicaSetAvailable"
		}
	}
	return false
}

func (c *DeploymentVersionController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	klog.V(4).Infof("DeploymentVersionController sync started")
	defer klog.V(4).Infof("DeploymentVersionController sync finished")

	opSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if opSpec.ManagementState != operatorapi.Managed {
		return nil
	}

	deployment, err := c.deploymentInformer.Lister().Deployments(c.controlPlaneNamespace).Get(c.controllerDeploymentName)
	if err != nil {
		return fmt.Errorf("could not get Deployment %s in Namespace %s: %w", c.controllerDeploymentName, c.controlPlaneNamespace, err)
	}

	desiredVersion := deployment.Annotations[desiredVersionAnnotation]
	actualVersion := deployment.Annotations[versionAnnotation]

	// This operator adds desiredVersionAnnotation annotation with its version for sure; if the
	// version from Annotations is not the same as operator version, we look at some outdated
	// deployment generated by another (previous) operator instance.
	if desiredVersion != status.VersionForOperatorFromEnv() {
		klog.V(4).Infof("DeploymentVersionController: desiredVersion mismatch: \"%s\" vs \"%s\"", desiredVersion, status.VersionForOperatorFromEnv())
		return nil
	}

	// If versions from versionAnnotation and desiredVersionAnnotation annotations are equal,
	// we have already populated these annotations before, do nothing now.
	if actualVersion == desiredVersion {
		klog.V(4).Infof("DeploymentVersionController: version \"%s\" is already populated, nothing to do", desiredVersion)
		return nil
	}

	if hasFinishedProgressing(deployment) {
		updatedDeployment := setVersionAnnotation(deployment, desiredVersion)
		err := c.updateDeployment(ctx, updatedDeployment)
		if err != nil {
			return err
		}
		klog.V(2).Infof("DeploymentVersionController: deployment updated with version %s", desiredVersion)
	} else {
		klog.V(4).Infof("DeploymentVersionController: deployment update is in progress ...")
	}
	return nil
}

func (c *DeploymentVersionController) updateDeployment(ctx context.Context, deployment *appsv1.Deployment) error {
	_, err := c.controlPlaneKubeClient.AppsV1().Deployments(c.controlPlaneNamespace).Update(ctx, deployment, metav1.UpdateOptions{})
	if err != nil {
		klog.Errorf("error updating deployment object %s in namespace %s: %v", deployment.Name, c.controlPlaneNamespace, err)
		return err
	}
	return nil
}

func setVersionAnnotation(deployment *appsv1.Deployment, version string) *appsv1.Deployment {
	// Create a deep copy of the PersistentVolume to avoid modifying the cached object
	deploymentCopy := deployment.DeepCopy()

	// Ensure the deployment has an annotations map
	if deploymentCopy.Annotations == nil {
		deploymentCopy.Annotations = make(map[string]string)
	}

	// Set or update the tag hash annotation
	deploymentCopy.Annotations[versionAnnotation] = version

	return deploymentCopy
}
