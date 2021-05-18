package buildutil

import (
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	kvalidation "k8s.io/apimachinery/pkg/util/validation"

	buildv1 "github.com/openshift/api/build/v1"

	"github.com/openshift/library-go/pkg/build/naming"
)

var (
	// buildVolumeMountPath is where user defined BuildVolumes get mounted
	buildVolumeMountPath = "/var/run/openshift.io/volumes"
	// buildVolumeSuffix is a suffix for BuildVolume names
	buildVolumeSuffix = "user-build-volume"
)

// GetInputReference returns the From ObjectReference associated with the
// BuildStrategy.
func GetInputReference(strategy buildv1.BuildStrategy) *corev1.ObjectReference {
	switch {
	case strategy.SourceStrategy != nil:
		return &strategy.SourceStrategy.From
	case strategy.DockerStrategy != nil:
		return strategy.DockerStrategy.From
	case strategy.CustomStrategy != nil:
		return &strategy.CustomStrategy.From
	default:
		return nil
	}
}

// GetBuildEnv gets the build strategy environment
func GetBuildEnv(build *buildv1.Build) []corev1.EnvVar {
	switch {
	case build.Spec.Strategy.SourceStrategy != nil:
		return build.Spec.Strategy.SourceStrategy.Env
	case build.Spec.Strategy.DockerStrategy != nil:
		return build.Spec.Strategy.DockerStrategy.Env
	case build.Spec.Strategy.CustomStrategy != nil:
		return build.Spec.Strategy.CustomStrategy.Env
	case build.Spec.Strategy.JenkinsPipelineStrategy != nil:
		return build.Spec.Strategy.JenkinsPipelineStrategy.Env
	default:
		return nil
	}
}

// SetBuildEnv replaces the current build environment
func SetBuildEnv(build *buildv1.Build, env []corev1.EnvVar) {
	var oldEnv *[]corev1.EnvVar

	switch {
	case build.Spec.Strategy.SourceStrategy != nil:
		oldEnv = &build.Spec.Strategy.SourceStrategy.Env
	case build.Spec.Strategy.DockerStrategy != nil:
		oldEnv = &build.Spec.Strategy.DockerStrategy.Env
	case build.Spec.Strategy.CustomStrategy != nil:
		oldEnv = &build.Spec.Strategy.CustomStrategy.Env
	case build.Spec.Strategy.JenkinsPipelineStrategy != nil:
		oldEnv = &build.Spec.Strategy.JenkinsPipelineStrategy.Env
	default:
		return
	}
	*oldEnv = env
}

// FindTriggerPolicy retrieves the BuildTrigger(s) of a given type from a build configuration.
// Returns nil if no matches are found.
func FindTriggerPolicy(triggerType buildv1.BuildTriggerType, config *buildv1.BuildConfig) (buildTriggers []buildv1.BuildTriggerPolicy) {
	for _, specTrigger := range config.Spec.Triggers {
		if specTrigger.Type == triggerType {
			buildTriggers = append(buildTriggers, specTrigger)
		}
	}
	return buildTriggers
}

// ConfigNameForBuild returns the name of the build config from a
// build name.
func ConfigNameForBuild(build *buildv1.Build) string {
	if build == nil {
		return ""
	}
	if build.Annotations != nil {
		if _, exists := build.Annotations[buildv1.BuildConfigAnnotation]; exists {
			return build.Annotations[buildv1.BuildConfigAnnotation]
		}
	}
	if _, exists := build.Labels[buildv1.BuildConfigLabel]; exists {
		return build.Labels[buildv1.BuildConfigLabel]
	}
	return build.Labels[buildv1.BuildConfigLabelDeprecated]
}

// NameForBuildVolume returns a valid pod volume name for the provided build volume name.
func NameForBuildVolume(objName string) string {
	// Volume names must be a valid DNS Label - see https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
	return naming.GetName(strings.ToLower(objName), buildVolumeSuffix, kvalidation.DNS1123LabelMaxLength)
}

// PathForBuildVolume returns the path in the builder container where the build volume is mounted.
// This should not be confused with the destination path for the volume inside buildah's runtime environment.
func PathForBuildVolume(objName string) string {
	return filepath.Join(buildVolumeMountPath, NameForBuildVolume(objName))
}
