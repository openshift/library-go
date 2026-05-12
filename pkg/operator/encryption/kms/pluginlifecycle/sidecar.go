package pluginlifecycle

import (
	"fmt"
	"sort"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

// sidecarProvider abstracts the construction of a KMS plugin sidecar container for a specific provider (e.g. Vault).
type sidecarProvider interface {
	// Name returns the identifier used to name the sidecar container and locate its volume mounts.
	Name() string
	// BuildSidecarContainer returns a fully configured sidecar container ready to be injected into the API server pod
	BuildSidecarContainer() (corev1.Container, error)
}

// newSidecarProvider creates a provider-specific SidecarProvider for the given keyID, UDS endpoint, and plugin configuration.
func newSidecarProvider(keyID string, udsPath string, pluginConfig *configv1.KMSPluginConfig) (sidecarProvider, error) {
	switch pluginConfig.Type {
	case configv1.VaultKMSProvider:
		return newVaultSidecarProvider("vault-kms-plugin", keyID, udsPath, pluginConfig)
	default:
		return nil, fmt.Errorf("unsupported KMS plugin configuration")
	}
}

// AddKMSPluginSidecarToPodSpec discovers KMS plugins from the encryption-config secret and injects a sidecar container for each one into the pod spec. No-op when the KMS feature gate is disabled or no KMS plugins are configured.
func AddKMSPluginSidecarToPodSpec(podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, secretLister corev1listers.SecretLister) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	if containerName == "" {
		return fmt.Errorf("container name cannot be empty")
	}

	encryptionConfigurationSecret, err := secretLister.Secrets(encryptionConfigNamespace).Get(encryptionConfigSecretName)
	if apierrors.IsNotFound(err) {
		klog.V(4).Infof("skipping KMS sidecar injection: %s/%s secret not found", encryptionConfigNamespace, encryptionConfigSecretName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get %s/%s secret: %w", encryptionConfigNamespace, encryptionConfigSecretName, err)
	}

	encryptionConfigurationBytes, ok := encryptionConfigurationSecret.Data["encryption-config"]
	if !ok {
		return fmt.Errorf("encryption-config key not found in secret %s/%s", encryptionConfigNamespace, encryptionConfigSecretName)
	}

	encryptionConfiguration, err := encoding.DecodeEncryptionConfiguration(encryptionConfigurationBytes)
	if err != nil {
		return fmt.Errorf("failed to decode EncryptionConfiguration from %s/%s secret: %w", encryptionConfigNamespace, encryptionConfigSecretName, err)
	}

	endpoints, err := kms.KMSendpointsByKeyID(encryptionConfiguration)
	if err != nil {
		return fmt.Errorf("failed to get KMS configurations: %w", err)
	}
	if len(endpoints) == 0 {
		klog.V(4).Infof("skipping KMS sidecar injection: no KMS plugins found in EncryptionConfiguration")
		return nil
	}

	klog.V(4).Infof("injecting %d KMS sidecar(s)", len(endpoints))

	sortedKeyIDs := make([]string, 0, len(endpoints))
	for keyID := range endpoints {
		sortedKeyIDs = append(sortedKeyIDs, keyID)
	}
	sort.Strings(sortedKeyIDs)

	for _, keyID := range sortedKeyIDs {
		udsPath := endpoints[keyID]

		pluginConfig, err := kms.ParsePluginConfig(encryptionConfigurationSecret, keyID)
		if err != nil {
			return fmt.Errorf("failed to parse plugin config for keyID %s: %w", keyID, err)
		}

		sidecarProvider, err := newSidecarProvider(keyID, udsPath, pluginConfig)
		if err != nil {
			return fmt.Errorf("failed to create a sidecar provider for keyID %s: %w", keyID, err)
		}

		if err := appendSidecarContainer(podSpec, sidecarProvider); err != nil {
			return err
		}

		if err := ensureSocketVolumeMount(podSpec, sidecarProvider.Name()); err != nil {
			return err
		}

		if err := ensureResourceDirVolumeMount(podSpec, sidecarProvider.Name()); err != nil {
			return err
		}
	}

	if err := ensureSocketVolumeMount(podSpec, containerName); err != nil {
		return err
	}

	return nil
}

func appendSidecarContainer(podSpec *corev1.PodSpec, provider sidecarProvider) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	container, err := provider.BuildSidecarContainer()
	if err != nil {
		return fmt.Errorf("failed to build sidecar container: %w", err)
	}

	podSpec.Containers = append(podSpec.Containers, container)
	return nil
}

func ensureResourceDirVolumeMount(podSpec *corev1.PodSpec, containerName string) error {
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
	for _, m := range container.VolumeMounts {
		if m.Name == "resource-dir" {
			return nil
		}
	}
	container.VolumeMounts = append(container.VolumeMounts,
		corev1.VolumeMount{
			Name:      "resource-dir",
			MountPath: "/etc/kubernetes/static-pod-resources",
			ReadOnly:  true,
		},
	)

	return nil
}

func ensureSocketVolumeMount(podSpec *corev1.PodSpec, containerName string) error {
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
	foundMount := false
	for _, m := range container.VolumeMounts {
		if m.Name == "kms-plugin-socket" {
			foundMount = true
			break
		}
	}
	if !foundMount {
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{
				Name:      "kms-plugin-socket",
				MountPath: "/var/run/kmsplugin",
			},
		)
	}

	// The volume mount in the container requires a volume in the podSpec
	return ensureSocketVolume(podSpec)
}

func ensureSocketVolume(podSpec *corev1.PodSpec) error {
	foundVolume := false
	for _, volume := range podSpec.Volumes {
		if volume.Name == "kms-plugin-socket" {
			foundVolume = true
			break
		}
	}

	if !foundVolume {
		podSpec.Volumes = append(podSpec.Volumes,
			corev1.Volume{
				Name: "kms-plugin-socket",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
	}

	return nil
}
