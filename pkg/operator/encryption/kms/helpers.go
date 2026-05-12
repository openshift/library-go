package kms

import (
	"fmt"
	"strconv"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

const pluginConfigDataKeyPrefix = "kms-plugin-config-"

// ToPluginConfigSecretDataKeyFor constructs the data key for storing a KMS plugin config in the encryption-config Secret.
// The keyID must be a valid non-negative integer string.
func ToPluginConfigSecretDataKeyFor(keyID string) (string, error) {
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return pluginConfigDataKeyPrefix + keyID, nil
}

// KeyIDFromPluginConfigSecretDataKey extracts the keyID from a kms-plugin-config data key.
// Returns the keyID and true if the key matches the "kms-plugin-config-<keyID>" pattern.
func KeyIDFromPluginConfigSecretDataKey(dataKey string) (string, bool, error) {
	keyID, found := strings.CutPrefix(dataKey, pluginConfigDataKeyPrefix)
	if !found || len(keyID) == 0 {
		return "", false, nil
	}
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", false, fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return keyID, true, nil
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

// KMSendpointsByKeyID walks through all resource configurations in the EncryptionConfiguration
// and collects every unique KMS provider, deduplicating by endpoint.
func KMSendpointsByKeyID(config *apiserverv1.EncryptionConfiguration) (map[string]string, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	byKeyID := map[string]string{}
	for _, resource := range config.Resources {
		for _, provider := range resource.Providers {
			if provider.KMS == nil {
				continue
			}
			keyID, err := GetKeyIDFromPluginName(provider.KMS.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key ID from provider name %q: %w", provider.KMS.Name, err)
			}
			byKeyID[keyID] = provider.KMS.Endpoint
		}
	}
	return byKeyID, nil
}

// GetKeyIDFromPluginName extracts the keyID from a KMS provider name.
func GetKeyIDFromPluginName(providerName string) (string, error) {
	parsed := strings.SplitN(providerName, "_", 2)
	if len(parsed) != 2 {
		return "", fmt.Errorf("invalid provider name %q: expected format keyID_resourceName", providerName)
	}
	return parsed[0], nil
}

// ParsePluginConfig extracts and decodes the provider-specific KMSPluginConfig for the given keyID from the encryption-config secret.
func ParsePluginConfig(secret *corev1.Secret, keyID string) (*configv1.KMSPluginConfig, error) {
	pluginConfigKey, err := ToPluginConfigSecretDataKeyFor(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin config secret data key for keyID %s: %w", keyID, err)
	}
	pluginConfigData, ok := secret.Data[pluginConfigKey]
	if !ok {
		return nil, fmt.Errorf("missing plugin config key %s in encryption-config secret", pluginConfigKey)
	}
	kmsPluginConfig, err := encoding.DecodeKMSPluginConfig(pluginConfigData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plugin config: %w", err)
	}
	return &kmsPluginConfig, nil
}
