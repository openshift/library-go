package deployment

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	appsv1 "github.com/openshift/api/apps/v1"
)

// ConfigSelector returns a label Selector which can be used to find all
// deployments for a DeploymentConfig.
//
// TODO: Using the annotation constant for now since the value is correct
// but we could consider adding a new constant to the public types.
func ConfigSelector(name string) labels.Selector {
	return labels.SelectorFromValidatedSet(labels.Set{appsv1.DeploymentConfigAnnotation: name})
}

// DeployerPodSelector returns a label Selector which can be used to find all
// deployer pods associated with a deployment with name.
func DeployerPodSelector(name string) labels.Selector {
	return labels.SelectorFromValidatedSet(labels.Set{appsv1.DeployerPodForDeploymentLabel: name})
}

// LatestDeploymentNameForConfig returns a stable identifier for deployment config
func LatestDeploymentNameForConfig(config *appsv1.DeploymentConfig) string {
	return LatestDeploymentNameForConfigAndVersion(config.Name, config.Status.LatestVersion)
}

// LatestDeploymentNameForConfigAndVersion returns a stable identifier for config based on its version.
func LatestDeploymentNameForConfigAndVersion(name string, version int64) string {
	return fmt.Sprintf("%s-%d", name, version)
}

// ActiveDeployment returns the latest complete deployment, or nil if there is
// no such deployment. The active deployment is not always the same as the
// latest deployment.
func ActiveDeployment(input []*corev1.ReplicationController) *corev1.ReplicationController {
	var activeDeployment *corev1.ReplicationController
	var lastCompleteDeploymentVersion int64 = 0
	for i := range input {
		deployment := input[i]
		deploymentVersion := DeploymentVersionFor(deployment)
		if IsCompleteDeployment(deployment) && deploymentVersion > lastCompleteDeploymentVersion {
			activeDeployment = deployment
			lastCompleteDeploymentVersion = deploymentVersion
		}
	}
	return activeDeployment
}

// IsCompleteDeployment returns true if the passed deployment is in state complete.
func IsCompleteDeployment(deployment runtime.Object) bool {
	return DeploymentStatusFor(deployment) == appsv1.DeploymentStatusComplete
}

// IsFailedDeployment returns true if the passed deployment failed.
func IsFailedDeployment(deployment runtime.Object) bool {
	return DeploymentStatusFor(deployment) == appsv1.DeploymentStatusFailed
}

// IsTerminatedDeployment returns true if the passed deployment has terminated (either
// complete or failed).
func IsTerminatedDeployment(deployment runtime.Object) bool {
	return IsCompleteDeployment(deployment) || IsFailedDeployment(deployment)
}

func IsDeploymentCancelled(deployment runtime.Object) bool {
	value := AnnotationFor(deployment, appsv1.DeploymentCancelledAnnotation)
	return strings.EqualFold(value, "true")
}

func DeploymentStatusFor(deployment runtime.Object) appsv1.DeploymentStatus {
	return appsv1.DeploymentStatus(AnnotationFor(deployment, appsv1.DeploymentStatusAnnotation))
}

func DeploymentStatusReasonFor(obj runtime.Object) string {
	return AnnotationFor(obj, appsv1.DeploymentStatusReasonAnnotation)
}

func DeploymentVersionFor(obj runtime.Object) int64 {
	v, err := strconv.ParseInt(AnnotationFor(obj, appsv1.DeploymentVersionAnnotation), 10, 64)
	if err != nil {
		return -1
	}
	return v
}

func DeploymentConfigNameFor(obj runtime.Object) string {
	return AnnotationFor(obj, appsv1.DeploymentConfigAnnotation)
}

// AnnotationFor returns the annotation with key for obj.
func AnnotationFor(obj runtime.Object, key string) string {
	objectMeta, err := meta.Accessor(obj)
	if err != nil {
		return ""
	}
	if objectMeta == nil || reflect.ValueOf(objectMeta).IsNil() {
		return ""
	}
	return objectMeta.GetAnnotations()[key]
}

type ByLatestVersionAsc []*corev1.ReplicationController

func (d ByLatestVersionAsc) Len() int      { return len(d) }
func (d ByLatestVersionAsc) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d ByLatestVersionAsc) Less(i, j int) bool {
	return DeploymentVersionFor(d[i]) < DeploymentVersionFor(d[j])
}

// ByLatestVersionDesc sorts deployments by LatestVersion descending.
type ByLatestVersionDesc []*corev1.ReplicationController

func (d ByLatestVersionDesc) Len() int      { return len(d) }
func (d ByLatestVersionDesc) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d ByLatestVersionDesc) Less(i, j int) bool {
	return DeploymentVersionFor(d[j]) < DeploymentVersionFor(d[i])
}
