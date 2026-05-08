package kms

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

var kmsEndpointRegexp = regexp.MustCompile(`^unix:///var/run/kmsplugin/kms-(\d+)\.sock$`)

const providerConfigDataKeyPrefix = "kms-provider-config-"
const credentialDataKeyPrefix = "kms-secret-data-"
const credentialsDir = "/etc/kubernetes/static-pod-resources/secrets/encryption-config"

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

// ToCredentialSecretDataKeyFor constructs the data key for storing KMS credentials in the encryption-config Secret.
// The keyID must be a valid non-negative integer string.
func ToCredentialSecretDataKeyFor(keyID string) (string, error) {
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return credentialDataKeyPrefix + keyID, nil
}

// KeyIDFromCredentialSecretDataKey extracts the keyID from a kms-secret-data data key.
// Returns the keyID and true if the key matches the "kms-secret-data-<keyID>" pattern.
func KeyIDFromCredentialSecretDataKey(dataKey string) (string, bool, error) {
	keyID, found := strings.CutPrefix(dataKey, credentialDataKeyPrefix)
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

func findFirstKMSConfiguration(config *apiserverv1.EncryptionConfiguration) *apiserverv1.KMSConfiguration {
	for _, resource := range config.Resources {
		for _, provider := range resource.Providers {
			if provider.KMS != nil {
				return provider.KMS
			}
		}
	}
	return nil
}

func parseKeyIDFromEndpoint(endpoint string) (string, error) {
	matches := kmsEndpointRegexp.FindStringSubmatch(endpoint)
	if matches == nil {
		return "", fmt.Errorf("unexpected KMS endpoint format: %s", endpoint)
	}
	return matches[1], nil
}

func parseProviderConfig(secret *corev1.Secret, kmsConfiguration *apiserverv1.KMSConfiguration) (*configv1.KMSConfig, error) {
	keyID, err := parseKeyIDFromEndpoint(kmsConfiguration.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID from endpoint: %w", err)
	}
	providerConfigKey, err := ToProviderConfigSecretDataKeyFor(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider config secret key ID from endpoint: %w", err)
	}
	providerConfigData, ok := secret.Data[providerConfigKey]
	if !ok {
		return nil, fmt.Errorf("missing provider config key %s in encryption-config secret", providerConfigKey)
	}
	kmsConfig, err := encoding.DecodeKMSConfig(providerConfigData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode provider config: %w", err)
	}
	return kmsConfig, nil
}

func parseSecretDataPath(kmsConfiguration *apiserverv1.KMSConfiguration) (string, error) {
	keyID, err := parseKeyIDFromEndpoint(kmsConfiguration.Endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse key ID from endpoint: %w", err)
	}
	return filepath.Join(credentialsDir, credentialDataKeyPrefix+keyID), nil
}
