package preflight

import (
	corev1 "k8s.io/api/core/v1"
)

const podResourceDirVolumeName = "pod-resource-dir"

var staticPodResourceDirSubpathMounts = []corev1.VolumeMount{
	{
		Name:      podResourceDirVolumeName,
		MountPath: "/etc/kubernetes/static-pod-resources/secrets",
		SubPath:   "secrets",
		ReadOnly:  true,
	},
	{
		Name:      podResourceDirVolumeName,
		MountPath: "/etc/kubernetes/static-pod-resources/configmaps",
		SubPath:   "configmaps",
		ReadOnly:  true,
	},
}

// ensureStaticPodInitContainerResourceMounts adds revision-scoped resource-dir
// subpath mounts to init containers. KMS plugin sidecars are injected as init
// containers and need the same mounts as the preflight checker container.
func ensureStaticPodInitContainerResourceMounts(podSpec *corev1.PodSpec) {
	for i := range podSpec.InitContainers {
		for _, mount := range staticPodResourceDirSubpathMounts {
			podSpec.InitContainers[i].VolumeMounts = appendVolumeMountIfMissing(podSpec.InitContainers[i].VolumeMounts, mount)
		}
	}
}

func appendVolumeMountIfMissing(mounts []corev1.VolumeMount, mount corev1.VolumeMount) []corev1.VolumeMount {
	for _, existing := range mounts {
		if existing.Name == mount.Name && existing.MountPath == mount.MountPath && existing.SubPath == mount.SubPath {
			return mounts
		}
	}
	return append(mounts, mount)
}
