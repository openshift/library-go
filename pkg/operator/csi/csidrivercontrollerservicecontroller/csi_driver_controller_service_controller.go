package csidrivercontrollerservicecontroller

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	opv1 "github.com/openshift/api/operator/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	driverImageEnvName        = "DRIVER_IMAGE"
	provisionerImageEnvName   = "PROVISIONER_IMAGE"
	attacherImageEnvName      = "ATTACHER_IMAGE"
	resizerImageEnvName       = "RESIZER_IMAGE"
	snapshotterImageEnvName   = "SNAPSHOTTER_IMAGE"
	livenessProbeImageEnvName = "LIVENESS_PROBE_IMAGE"

	infraConfigName = "cluster"
)

// CSIDriverControllerServiceController is a controller that deploys a CSI Controller Service to a given namespace.
//
// The CSI Controller Service is represented by a Deployment. This Deployment deploys a pod with the CSI driver
// and sidecars containers (provisioner, attacher, resizer, snapshotter, liveness-probe).
//
// On every sync, this controller reads the Deployment from a static file and overrides a few fields:
//
// 1. Container image locations
//
// The controller will replace the images specified in the static file if their name follows a certain nomenclature AND its
// respective environemnt variable is set. This is a list of environment variables that the controller understands:
//
// DRIVER_IMAGE
// PROVISIONER_IMAGE
// ATTACHER_IMAGE
// RESIZER_IMAGE
// SNAPSHOTTER_IMAGE
// LIVENESS_PROBE_IMAGE
//
// The names above should be wrapped by a ${}, e.g., ${DIVER_IMAGE} in static file.
//
// 2. Log level
//
// The controller can also override the log level passed in to the CSI driver container.
// In order to do that, the placeholder ${LOG_LEVEL} from the manifest file is replaced with the value specified
// in the OperatorClient resource (Spec.LogLevel).
//
// 3. Cluster ID
//
// The placeholder ${CLUSTER_ID} specified in the static file can also be replaced if optionalConfigInformer is not nil.
// This is mostly used by CSI drivers to tag volumes and snapshots so that those resources can be cleaned up on cluster deletion.
//
// This controller produces the following conditions:
//
// <name>Available: indicates that the CSI Controller Service was successfully deployed and at least one Deployment replica is available.
// <name>Progressing: indicates that the CSI Controller Service is being deployed.
// <name>Degraded: produced when the sync() method returns an error.
type CSIDriverControllerServiceController struct {
	name           string
	manifest       []byte
	operatorClient v1helpers.OperatorClient
	kubeClient     kubernetes.Interface
	deployInformer appsinformersv1.DeploymentInformer
	// Optional, used by CSI drivers to tag volumes and snapshots
	optionalConfigInformer configinformers.SharedInformerFactory
}

func NewCSIDriverControllerServiceController(
	name string,
	manifest []byte,
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	deployInformer appsinformersv1.DeploymentInformer,
	optionalConfigInformer configinformers.SharedInformerFactory,
	recorder events.Recorder,
) factory.Controller {
	c := &CSIDriverControllerServiceController{
		name:                   name,
		manifest:               manifest,
		operatorClient:         operatorClient,
		kubeClient:             kubeClient,
		deployInformer:         deployInformer,
		optionalConfigInformer: optionalConfigInformer,
	}

	informers := []factory.Informer{
		operatorClient.Informer(),
		deployInformer.Informer(),
	}
	if c.optionalConfigInformer != nil {
		informers = append(informers, optionalConfigInformer.Config().V1().Infrastructures().Informer())
	}

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
		recorder.WithComponentSuffix("csi-driver-controller-service_"+strings.ToLower(name)),
	)
}

func (c *CSIDriverControllerServiceController) Name() string {
	return c.name
}

func (c *CSIDriverControllerServiceController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	var clusterID string
	if c.optionalConfigInformer != nil {
		infra, err := c.optionalConfigInformer.Config().V1().Infrastructures().Lister().Get(infraConfigName)
		if err != nil {
			return err
		}
		clusterID = infra.Status.InfrastructureName
	}

	manifest := replacePlaceholders(c.manifest, opSpec, clusterID)
	required := resourceread.ReadDeploymentV1OrDie(manifest)

	deployment, _, err := resourceapply.ApplyDeployment(
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
		availableCondition.Message = "Waiting for Deployment to deploy the CSI Controller Service"
		availableCondition.Reason = "Deploying"
	}

	progressingCondition := opv1.OperatorCondition{
		Type:   c.name + opv1.OperatorStatusTypeProgressing,
		Status: opv1.ConditionFalse,
	}

	if ok, msg := isProgressing(opStatus, deployment); ok {
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

func isProgressing(status *opv1.OperatorStatus, deployment *appsv1.Deployment) (bool, string) {
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

func replacePlaceholders(manifest []byte, spec *opv1.OperatorSpec, clusterID string) []byte {
	pairs := []string{}

	// Replace container images by env vars if they are set
	csiDriver := os.Getenv(driverImageEnvName)
	if csiDriver != "" {
		pairs = append(pairs, []string{"${DRIVER_IMAGE}", csiDriver}...)
	}

	provisioner := os.Getenv(provisionerImageEnvName)
	if provisioner != "" {
		pairs = append(pairs, []string{"${PROVISIONER_IMAGE}", provisioner}...)
	}

	attacher := os.Getenv(attacherImageEnvName)
	if attacher != "" {
		pairs = append(pairs, []string{"${ATTACHER_IMAGE}", attacher}...)
	}

	resizer := os.Getenv(resizerImageEnvName)
	if resizer != "" {
		pairs = append(pairs, []string{"${RESIZER_IMAGE}", resizer}...)
	}

	snapshotter := os.Getenv(snapshotterImageEnvName)
	if snapshotter != "" {
		pairs = append(pairs, []string{"${SNAPSHOTTER_IMAGE}", snapshotter}...)
	}

	livenessProbe := os.Getenv(livenessProbeImageEnvName)
	if livenessProbe != "" {
		pairs = append(pairs, []string{"${LIVENESS_PROBE_IMAGE}", livenessProbe}...)
	}

	// Cluster ID
	pairs = append(pairs, []string{"${CLUSTER_ID}", clusterID}...)

	// Log level
	logLevel := loglevel.LogLevelToVerbosity(spec.LogLevel)
	pairs = append(pairs, []string{"${LOG_LEVEL}", strconv.Itoa(logLevel)}...)

	replaced := strings.NewReplacer(pairs...).Replace(string(manifest))
	return []byte(replaced)
}
