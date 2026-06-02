package pluginlifecycle

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"
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

// newSidecarProvider creates a provider-specific SidecarProvider for the given keyID, UDS endpoint, and plugin configuration.
func newSidecarProvider(keyID string, udsPath string, pluginConfig configv1.KMSPluginConfig) (sidecarProvider, error) {
	switch pluginConfig.Type {
	case configv1.VaultKMSProvider:
		return newVaultSidecarProvider("vault-kms-plugin", keyID, udsPath, pluginConfig.Vault)
	default:
		return nil, fmt.Errorf("unsupported KMS plugin configuration")
	}
}

// AddKMSPluginSidecarToPodSpec discovers KMS plugins from the encryption-config secret and injects a sidecar container for each one into the pod spec.
// It is a no-op when the KMSEncryption feature gate is not enabled or the encryption-config secret does not exist.
// It uses an uncached client to avoid injecting sidecars based on a stale encryption configuration.
func AddKMSPluginSidecarToPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	if containerName == "" {
		return fmt.Errorf("container name cannot be empty")
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

	encryptionConfigurationSecret, err := secretClient.Secrets(encryptionConfigNamespace).Get(ctx, encryptionConfigSecretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		klog.V(4).Infof("skipping KMS sidecar injection: %s/%s secret not found", encryptionConfigNamespace, encryptionConfigSecretName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get %s/%s secret: %w", encryptionConfigNamespace, encryptionConfigSecretName, err)
	}

	encryptionConfig, err := encryptiondata.FromSecret(encryptionConfigurationSecret)
	if err != nil {
		return fmt.Errorf("failed to extract encryption config from %s/%s secret: %w", encryptionConfigNamespace, encryptionConfigSecretName, err)
	}

	kmsConfigurations, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(encryptionConfig)
	if err != nil {
		return fmt.Errorf("failed to get KMS configurations: %w", err)
	}
	if len(kmsConfigurations) == 0 {
		klog.V(4).Infof("skipping KMS sidecar injection: no KMS plugins found in EncryptionConfiguration")
		return nil
	}

	klog.V(4).Infof("injecting %d KMS sidecar(s)", len(kmsConfigurations))

	socketVolumeMount := corev1.VolumeMount{Name: kmsPluginSocketVolumeName, MountPath: kmsPluginSocketMountPath, ReadOnly: false}
	for _, kmsConfiguration := range kmsConfigurations {
		// ExtractUniqueAndSortedKMSConfigurations function rewrites the .Name field to include only the key ID
		keyID := kmsConfiguration.Name
		udsPath := kmsConfiguration.Endpoint

		pluginConfig, ok := encryptionConfig.KMSPlugins[keyID]
		if !ok {
			return fmt.Errorf("missing plugin config for keyID %s", keyID)
		}

		sidecarProvider, err := newSidecarProvider(keyID, udsPath, pluginConfig)
		if err != nil {
			return fmt.Errorf("failed to create a sidecar provider for keyID %s: %w", keyID, err)
		}

		if err := ensureSidecarContainer(podSpec, sidecarProvider); err != nil {
			return err
		}

		if err := ensureVolumeMountInContainer(podSpec.InitContainers, sidecarProvider.Name(), socketVolumeMount); err != nil {
			return err
		}
	}

	if err := ensureVolumeMountInContainer(podSpec.Containers, containerName, socketVolumeMount); err != nil {
		return err
	}

	// The volume mount in the kube-apiserver and KMS plugin containers requires a volume in the podSpec
	ensureSocketVolume(podSpec)

	return nil
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

func ensureSocketVolume(podSpec *corev1.PodSpec) {
	for _, volume := range podSpec.Volumes {
		if volume.Name == kmsPluginSocketVolumeName {
			return
		}
	}

	podSpec.Volumes = append(podSpec.Volumes,
		corev1.Volume{
			Name: kmsPluginSocketVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	)
}
