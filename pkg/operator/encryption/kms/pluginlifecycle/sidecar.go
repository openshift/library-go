package pluginlifecycle

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
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

const (
	vaultSidecarPrefix = "vault-kms-plugin"
	healthReporterName = "kms-health-reporter"
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
		return newVaultSidecarProvider(vaultSidecarPrefix, keyID, udsPath, pluginConfig.Vault, refData)
	default:
		return nil, fmt.Errorf("unsupported KMS plugin configuration")
	}
}

// EnsureKMSPluginSidecarInStaticPodSpec reconciles KMS plugin sidecar containers in a kube-apiserver static pod spec.
// It removes all KMS-managed resources (sidecars, volumes, volume mounts) and then re-adds exactly what the
// current encryption config requires, ensuring stale resources from a previous configuration are pruned.
//
// Static pods access KMS plugin data through the resource-dir volume, which the static pod revision controller
// populates on disk from the encryption-config Secret. Because those files are owned by root, each sidecar
// is configured to run as UID 0.
//
// It is a no-op when the KMSEncryption feature gate is not enabled or the encryption-config secret does not exist.
// The secretClient should be uncached to avoid injecting sidecars based on a stale encryption configuration.
func EnsureKMSPluginSidecarInStaticPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, diskSecretName string, operatorBinary string, operatorImage string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
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

// EnsureKMSPluginSidecarInPodSpec reconciles KMS plugin sidecar containers in an aggregated API server pod spec (e.g., openshift-apiserver, oauth-apiserver).
// It removes all KMS-managed resources (sidecars, volumes, volume mounts) and then re-adds exactly what the
// current encryption config requires, ensuring stale resources from a previous configuration are pruned.
//
// It is a no-op when the KMSEncryption feature gate is not enabled or the encryption-config secret does not exist.
// The secretClient should be uncached to avoid injecting sidecars based on a stale encryption configuration.
func EnsureKMSPluginSidecarInPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, operatorBinary string, operatorImage string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
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

func isKMSManagedContainer(name string) bool {
	// Check if this is the KMS health reporter sidecar
	if name == health.Subcommand {
		return true
	}
	// Check if this is a Vault KMS plugin sidecar
	if strings.HasPrefix(name, vaultSidecarPrefix+"-") {
		return true
	}
	return false
}

func isKMSManagedVolume(name string) bool {
	return name == kmsPluginSocketVolumeName || name == referenceDataVolumeName
}

// removeAllKMSManagedResources removes all KMS-managed initContainers, volumes, and volume mounts from the pod spec.
// IMPORTANT: When adding new KMS resource types (e.g., ephemeral containers, config maps), update this function
// and the corresponding isKMSManaged* helper functions. Failure to do so breaks the pre-ready revision checks
// that rely on this Ensure function to achieve the desired state.
func removeAllKMSManagedResources(podSpec *corev1.PodSpec, containerName string) {
	filtered := podSpec.InitContainers[:0]
	for _, c := range podSpec.InitContainers {
		if !isKMSManagedContainer(c.Name) {
			filtered = append(filtered, c)
		}
	}
	podSpec.InitContainers = filtered

	filteredVolumes := podSpec.Volumes[:0]
	for _, v := range podSpec.Volumes {
		if !isKMSManagedVolume(v.Name) {
			filteredVolumes = append(filteredVolumes, v)
		}
	}
	podSpec.Volumes = filteredVolumes

	for i, c := range podSpec.Containers {
		if c.Name == containerName {
			mounts := c.VolumeMounts[:0]
			for _, m := range c.VolumeMounts {
				if m.Name != kmsPluginSocketVolumeName {
					mounts = append(mounts, m)
				}
			}
			podSpec.Containers[i].VolumeMounts = mounts
			break
		}
	}
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
