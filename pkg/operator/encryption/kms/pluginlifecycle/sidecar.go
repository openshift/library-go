package pluginlifecycle

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/ptr"
)

const (
	resourceDirVolumeName   = "resource-dir"
	referenceDataVolumeName = "kms-plugins-data"
	referenceDataMountPath  = "/var/run/secrets/kms-plugin"
	resourcesDir            = "/etc/kubernetes/static-pod-resources"
)

const (
	kmsPluginSocketVolumeName = "kms-plugin-socket"
	kmsPluginSocketMountPath  = "/var/run/kmsplugin"
)

// sidecarProvider abstracts the construction of a KMS plugin sidecar container for a specific provider (e.g. Vault).
type sidecarProvider interface {
	// Name returns the identifier used to name the sidecar container and locate its volume mounts.
	Name() string
	// BuildSidecarContainer returns a fully configured sidecar container ready to be injected into the API server pod
	BuildSidecarContainer() (corev1.Container, error)
}

// newSidecarProvider creates a provider-specific sidecarProvider for the given keyID and plugin configuration,
// wiring in reference data (secrets, configmaps) via the referenceDataResolver.
func newSidecarProvider(keyID string, udsPath string, pluginConfig configv1.KMSPluginConfig, refData *referenceDataResolver) (sidecarProvider, error) {
	switch pluginConfig.Type {
	case configv1.VaultKMSProvider:
		return newVaultSidecarProvider("vault-kms-plugin", keyID, udsPath, pluginConfig.Vault, refData)
	default:
		return nil, fmt.Errorf("unsupported KMS plugin configuration")
	}
}

// AddKMSPluginSidecarToStaticPodSpec injects KMS plugin sidecar containers into a kube-apiserver static pod spec.
//
// Static pods access KMS plugin data through the resource-dir volume, which the static pod revision controller
// populates on disk from the encryption-config Secret. Because those files are owned by root, each sidecar
// is configured to run as UID 0.
//
// It is a no-op when the KMSEncryption feature gate is not enabled or the encryption-config secret does not exist.
// The secretClient should be uncached to avoid injecting sidecars based on a stale encryption configuration.
func AddKMSPluginSidecarToStaticPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, diskSecretName string, operatorBinary string, operatorImage string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
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

	return NewKMSPluginBuilder().
		FromEncryptionConfigSecret(encryptionConfigNamespace, encryptionConfigSecretName, secretClient).
		AsStaticPod().
		WithDiskSecretName(diskSecretName).
		WithHealthReporter(operatorBinary, operatorImage).
		Apply(ctx, podSpec, containerName)
}

// AddKMSPluginSidecarToPodSpec injects KMS plugin sidecar containers into an aggregated API server pod spec (e.g., openshift-apiserver, oauth-apiserver).
//
// It is a no-op when the KMSEncryption feature gate is not enabled or the encryption-config secret does not exist.
// The secretClient should be uncached to avoid injecting sidecars based on a stale encryption configuration.
func AddKMSPluginSidecarToPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, operatorBinary string, operatorImage string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
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

	return NewKMSPluginBuilder().
		FromEncryptionConfigSecret(encryptionConfigNamespace, encryptionConfigSecretName, secretClient).
		WithHealthReporter(operatorBinary, operatorImage).
		Apply(ctx, podSpec, containerName)
}

func ensureSidecarContainer(podSpec *corev1.PodSpec, provider sidecarProvider) error {
	sidecar, err := provider.BuildSidecarContainer()
	if err != nil {
		return fmt.Errorf("failed to build sidecar container: %w", err)
	}

	for i, container := range podSpec.InitContainers {
		if container.Name == sidecar.Name {
			podSpec.InitContainers[i] = sidecar
			return nil
		}
	}

	podSpec.InitContainers = append(podSpec.InitContainers, sidecar)
	return nil
}

func ensureVolumeMountInContainer(containers []corev1.Container, containerName string, volumeMount corev1.VolumeMount) error {
	containerIndex := -1
	for i, container := range containers {
		if container.Name == containerName {
			containerIndex = i
			break
		}
	}

	if containerIndex < 0 {
		return fmt.Errorf("container %s not found", containerName)
	}

	container := &containers[containerIndex]
	for _, m := range container.VolumeMounts {
		if m.Name == volumeMount.Name {
			if !equality.Semantic.DeepEqual(m, volumeMount) {
				return fmt.Errorf("container %s already has volume mount %s with different settings", containerName, volumeMount.Name)
			}
			return nil
		}
	}
	container.VolumeMounts = append(container.VolumeMounts, volumeMount)
	return nil
}

func ensureVolume(podSpec *corev1.PodSpec, volume corev1.Volume) error {
	for _, v := range podSpec.Volumes {
		if v.Name == volume.Name {
			if !equality.Semantic.DeepEqual(v, volume) {
				return fmt.Errorf("pod already has volume %s with different settings", v.Name)
			}
			return nil
		}
	}
	podSpec.Volumes = append(podSpec.Volumes, volume)
	return nil
}

func ensureSocketVolume(podSpec *corev1.PodSpec) error {
	volume := corev1.Volume{
		Name: kmsPluginSocketVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	return ensureVolume(podSpec, volume)
}

func ensureReferenceDataVolume(podSpec *corev1.PodSpec, secretName string) error {
	volume := corev1.Volume{
		Name: referenceDataVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: secretName,
			},
		},
	}
	return ensureVolume(podSpec, volume)
}

// setRunAsRoot sets RunAsUser=0 on the named container.
// The resource-dir files are owned by root and protected by SELinux, so the sidecar needs
// uid 0 and the proper SELinux label (indirectly obtained via host network) to read them.
func setRunAsRoot(containers []corev1.Container, containerName string) error {
	for i, c := range containers {
		if c.Name == containerName {
			if c.SecurityContext == nil {
				containers[i].SecurityContext = &corev1.SecurityContext{}
			}
			containers[i].SecurityContext.RunAsUser = ptr.To(int64(0))
			return nil
		}
	}
	return fmt.Errorf("container %s not found", containerName)
}
