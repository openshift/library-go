package csidrivercontroller

import (
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func (c *CSIDriverController) syncDeployment(spec *opv1.OperatorSpec, status *opv1.OperatorStatus) (*appsv1.Deployment, error) {
	deploy := c.getExpectedDeployment(spec)

	deploy, _, err := resourceapply.ApplyDeployment(
		c.kubeClient.AppsV1(),
		c.eventRecorder,
		deploy,
		resourcemerge.ExpectedDeploymentGeneration(deploy, status.Generations))
	if err != nil {
		return nil, err
	}

	return deploy, nil
}

func (c *CSIDriverController) syncDaemonSet(spec *opv1.OperatorSpec, status *opv1.OperatorStatus) (*appsv1.DaemonSet, error) {
	daemonSet := c.getExpectedDaemonSet(spec)

	daemonSet, _, err := resourceapply.ApplyDaemonSet(
		c.kubeClient.AppsV1(),
		c.eventRecorder,
		daemonSet,
		resourcemerge.ExpectedDaemonSetGeneration(daemonSet, status.Generations))
	if err != nil {
		return nil, err
	}

	return daemonSet, nil
}

func (c *CSIDriverController) syncStatus(
	meta *metav1.ObjectMeta,
	status *opv1.OperatorStatus,
	deployment *appsv1.Deployment,
	daemonSet *appsv1.DaemonSet) error {

	// Set the last generation change we dealt with
	status.ObservedGeneration = meta.Generation

	// Node Service is mandatory, so always set set generation in DaemonSet
	resourcemerge.SetDaemonSetGeneration(&status.Generations, daemonSet)

	// Set number of replicas of DaemonSet
	if daemonSet.Status.NumberUnavailable == 0 {
		status.ReadyReplicas = daemonSet.Status.UpdatedNumberScheduled
	}

	// Controller Service is not mandatory, so optionally set the generation in Deployment
	if c.controllerManifest != nil {
		// CSI Controller Service was deployed, set deployment generation
		resourcemerge.SetDeploymentGeneration(&status.Generations, deployment)

		// Add number of CSI controllers to the number of replicas ready
		if deployment != nil {
			if deployment.Status.UnavailableReplicas == 0 && daemonSet.Status.NumberUnavailable == 0 {
				status.ReadyReplicas += deployment.Status.UpdatedReplicas
			}
		}
	}

	// Finally, set the conditions

	// The operator does not have any prerequisites (at least now)
	v1helpers.SetOperatorCondition(&status.Conditions,
		opv1.OperatorCondition{
			Type:   fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypePrereqsSatisfied),
			Status: opv1.ConditionTrue,
		})

	// The operator is always upgradeable (at least now)
	v1helpers.SetOperatorCondition(&status.Conditions,
		opv1.OperatorCondition{
			Type:   fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeUpgradeable),
			Status: opv1.ConditionTrue,
		})

	// The operator is avaiable for now
	v1helpers.SetOperatorCondition(&status.Conditions,
		opv1.OperatorCondition{
			Type:   fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeAvailable),
			Status: opv1.ConditionTrue,
		})

	// Make it not available if daemonSet hasn't deployed the pods
	if !isDaemonSetAvailable(daemonSet) {
		v1helpers.SetOperatorCondition(&status.Conditions,
			opv1.OperatorCondition{
				Type:    fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeAvailable),
				Status:  opv1.ConditionFalse,
				Message: "Waiting for the DaemonSet to deploy the CSI Node Service",
				Reason:  "AsExpected",
			})
	}

	// Make it not available if deployment hasn't deployed the pods
	if c.controllerManifest != nil {
		if !isDeploymentAvailable(deployment) {
			v1helpers.SetOperatorCondition(&status.Conditions,
				opv1.OperatorCondition{
					Type:    fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeAvailable),
					Status:  opv1.ConditionFalse,
					Message: "Waiting for Deployment to deploy the CSI Controller Service",
					Reason:  "AsExpected",
				})
		}
	}

	// The operator is not progressing for now
	v1helpers.SetOperatorCondition(&status.Conditions,
		opv1.OperatorCondition{
			Type:   fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeProgressing),
			Status: opv1.ConditionFalse,
			Reason: "AsExpected",
		})

	isProgressing, msg := c.getDaemonSetProgress(status, daemonSet)
	if isProgressing {
		v1helpers.SetOperatorCondition(&status.Conditions,
			opv1.OperatorCondition{
				Type:    fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeProgressing),
				Status:  opv1.ConditionTrue,
				Message: msg,
				Reason:  "AsExpected",
			})
	}

	if c.controllerManifest != nil {
		// CSI Controller deployed, let's check its progressing state
		isProgressing, msg := c.getDeploymentProgress(status, deployment)
		if isProgressing {
			v1helpers.SetOperatorCondition(&status.Conditions,
				opv1.OperatorCondition{
					Type:    fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeProgressing),
					Status:  opv1.ConditionTrue,
					Message: msg,
					Reason:  "AsExpected",
				})
		}
	}

	return nil
}

func (c *CSIDriverController) getExpectedDeployment(spec *opv1.OperatorSpec) *appsv1.Deployment {
	manifest := replacePlaceHolders(c.controllerManifest, c.images, spec)
	return resourceread.ReadDeploymentV1OrDie(manifest)
}

func (c *CSIDriverController) getExpectedDaemonSet(spec *opv1.OperatorSpec) *appsv1.DaemonSet {
	manifest := replacePlaceHolders(c.nodeManifest, c.images, spec)
	return resourceread.ReadDaemonSetV1OrDie(manifest)
}

func (c *CSIDriverController) getDaemonSetProgress(status *opv1.OperatorStatus, daemonSet *appsv1.DaemonSet) (bool, string) {
	switch {
	case daemonSet == nil:
		return true, "Waiting for DaemonSet to be created"
	case daemonSet.Generation != daemonSet.Status.ObservedGeneration:
		return true, "Waiting for DaemonSet to act on changes"
	case daemonSet.Status.NumberUnavailable > 0:
		return true, "Waiting for DaemonSet to deploy node pods"
	}
	return false, ""
}

func (c *CSIDriverController) getDeploymentProgress(status *opv1.OperatorStatus, deployment *appsv1.Deployment) (bool, string) {
	var deploymentExpectedReplicas int32
	if deployment != nil && deployment.Spec.Replicas != nil {
		deploymentExpectedReplicas = *deployment.Spec.Replicas
	}

	switch {
	case deployment == nil:
		return true, "Waiting for Deployment to be created"
	case deployment.Generation != deployment.Status.ObservedGeneration:
		return true, "Waiting for Deployment to act on changes"
	case deployment.Status.UnavailableReplicas > 0:
		return true, "Waiting for Deployment to deploy controller pods"
	case deployment.Status.UpdatedReplicas < deploymentExpectedReplicas:
		return true, "Waiting for Deployment to update pods"
	case deployment.Status.AvailableReplicas < deploymentExpectedReplicas:
		return true, "Waiting for Deployment to deploy pods"
	}

	return false, ""
}

func isDaemonSetAvailable(d *appsv1.DaemonSet) bool {
	return d != nil && d.Status.NumberAvailable > 0
}

func isDeploymentAvailable(d *appsv1.Deployment) bool {
	return d != nil && d.Status.AvailableReplicas > 0
}

func replacePlaceHolders(manifest []byte, img images, spec *opv1.OperatorSpec) []byte {
	pairs := []string{}

	// Replace container images by env vars if they are set
	if img.csiDriver != "" {
		pairs = append(pairs, []string{"${DRIVER_IMAGE}", img.csiDriver}...)
	}

	if img.provisioner != "" {
		pairs = append(pairs, []string{"${PROVISIONER_IMAGE}", img.provisioner}...)
	}

	if img.attacher != "" {
		pairs = append(pairs, []string{"${ATTACHER_IMAGE}", img.attacher}...)
	}

	if img.resizer != "" {
		pairs = append(pairs, []string{"${RESIZER_IMAGE}", img.resizer}...)
	}

	if img.snapshotter != "" {
		pairs = append(pairs, []string{"${SNAPSHOTTER_IMAGE}", img.snapshotter}...)
	}

	if img.livenessProbe != "" {
		pairs = append(pairs, []string{"${LIVENESS_PROBE_IMAGE}", img.livenessProbe}...)
	}

	if img.nodeDriverRegistrar != "" {
		pairs = append(pairs, []string{"${NODE_DRIVER_REGISTRAR_IMAGE}", img.nodeDriverRegistrar}...)
	}

	// Log level
	logLevel := getLogLevel(spec.LogLevel)
	pairs = append(pairs, []string{"${LOG_LEVEL}", strconv.Itoa(logLevel)}...)

	replaced := strings.NewReplacer(pairs...).Replace(string(manifest))
	return []byte(replaced)
}

func getLogLevel(logLevel opv1.LogLevel) int {
	switch logLevel {
	case opv1.Normal, "":
		return 2
	case opv1.Debug:
		return 4
	case opv1.Trace:
		return 6
	case opv1.TraceAll:
		return 100
	default:
		return 2
	}
}
