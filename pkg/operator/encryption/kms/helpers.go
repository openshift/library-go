package kms

import (
	"fmt"
	"time"

	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	corev1 "k8s.io/api/core/v1"
)

const (
	DefaultEndpoint = "unix:///var/run/kmsplugin/kms.sock"
	DefaultTimeout  = 10 * time.Second
)

// AddKMSPluginVolumeAndMountToPodSpec conditionally adds the KMS plugin volume mount to the specified container.
// It assumes the pod spec does not already contain the KMS volume or mount; no deduplication is performed.
// Deprecated: this is a temporary solution to get KMS TP v1 out. We should come up with a different approach afterwards.
func AddKMSPluginVolumeAndMountToPodSpec(podSpec *corev1.PodSpec, containerName string, featureGateAccessor featuregates.FeatureGateAccess) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	if !featureGateAccessor.AreInitialFeatureGatesObserved() {
		return nil
	}

	featureGates, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return fmt.Errorf("failed to get feature gates: %w", err)
	}

	if !featureGates.Enabled(features.FeatureGateKMSEncryption) {
		return nil
	}

	containerIndex := -1
	for i, container := range podSpec.Containers {
		if container.Name == containerName {
			containerIndex = i
			break
		}
	}

	if containerIndex < 0 {
		return fmt.Errorf("container %s not found", containerName)
	}

	container := &podSpec.Containers[containerIndex]
	container.VolumeMounts = append(container.VolumeMounts,
		corev1.VolumeMount{
			Name:      "kms-plugin-socket",
			MountPath: "/var/run/kmsplugin",
		},
	)

	directoryOrCreate := corev1.HostPathDirectoryOrCreate
	podSpec.Volumes = append(podSpec.Volumes,
		corev1.Volume{
			Name: "kms-plugin-socket",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/kmsplugin",
					Type: &directoryOrCreate,
				},
			},
		},
	)

	return nil
}
