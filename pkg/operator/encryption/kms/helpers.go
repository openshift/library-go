package kms

import (
	"fmt"
	"strconv"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	corev1 "k8s.io/api/core/v1"
)

const providerConfigDataKeyPrefix = "kms-provider-config-"

// ToProviderConfigSecretDataKeyFor constructs the data key for storing a KMS provider config in the encryption-config Secret.
// The keyID must be a valid non-negative integer string.
func ToProviderConfigSecretDataKeyFor(keyID string) (string, error) {
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return providerConfigDataKeyPrefix + keyID, nil
}

// KeyIDFromProviderConfigSecretDataKey extracts the keyID from a kms-provider-config data key.
// Returns the keyID and true if the key matches the "kms-provider-config-<keyID>" pattern.
func KeyIDFromProviderConfigSecretDataKey(dataKey string) (string, bool, error) {
	keyID, found := strings.CutPrefix(dataKey, providerConfigDataKeyPrefix)
	if !found || len(keyID) == 0 {
		return "", false, nil
	}
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", false, fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return keyID, true, nil
}

// NeedsNewKey returns true if the KMS provider configuration has changed
// in a way that requires creating a new encryption key and migrating storage.
// Only fields that affect the Key Encryption Key (KEK) trigger migration.
// Fields like KMSPluginImage, TLS, and Authentication are non-migration fields.
func NeedsNewKey(latest, current *configv1.KMSConfig) bool {
	if latest.Type != current.Type {
		// TODO: Integrate this with pre-flight checker
		return true
	}
	if latest.Type == configv1.VaultKMSProvider {
		if latest.Vault.VaultAddress != current.Vault.VaultAddress ||
			latest.Vault.VaultNamespace != current.Vault.VaultNamespace ||
			latest.Vault.TransitMount != current.Vault.TransitMount ||
			latest.Vault.TransitKey != current.Vault.TransitKey {
			// TODO: Integrate this with pre-flight checker
			return true
		}
	}
	return false
}

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
