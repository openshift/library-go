package kms

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
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

// FetchCredentials reads the credential secret referenced by the KMS config
// from the openshift-config namespace. Returns nil if no credential reference
// is configured. Returns the secret data if found, or an error if the referenced
// secret is missing or has empty data.
func FetchCredentials(ctx context.Context, secretClient corev1client.SecretsGetter, kmsConfig *configv1.KMSConfig) (map[string][]byte, error) {
	if kmsConfig == nil {
		return nil, nil
	}

	switch kmsConfig.Type {
	case configv1.VaultKMSProvider:
		if kmsConfig.Vault == nil || len(kmsConfig.Vault.ApproleSecretRef.Name) == 0 {
			return nil, nil
		}
		credSecret, err := secretClient.Secrets("openshift-config").Get(ctx, kmsConfig.Vault.ApproleSecretRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get credential secret %s in openshift-config: %v", kmsConfig.Vault.ApproleSecretRef.Name, err)
		}
		if len(credSecret.Data) == 0 {
			return nil, fmt.Errorf("credential secret %s in openshift-config has empty data", kmsConfig.Vault.ApproleSecretRef.Name)
		}
		return credSecret.Data, nil
	default:
		return nil, nil
	}
}

// FetchConfigMapData reads the configmap referenced by the KMS config (e.g., TLS CA bundle).
// Returns nil if no configmap reference is configured.
// Returns the configmap data if found, or an error if the referenced configmap is missing or has empty data.
func FetchConfigMapData(ctx context.Context, configMapClient corev1client.ConfigMapsGetter, kmsConfig *configv1.KMSConfig) (map[string]string, error) {
	if kmsConfig == nil {
		return nil, nil
	}

	switch kmsConfig.Type {
	case configv1.VaultKMSProvider:
		if kmsConfig.Vault == nil || len(kmsConfig.Vault.TLSCA.Name) == 0 {
			return nil, nil
		}
		cm, err := configMapClient.ConfigMaps("openshift-config").Get(ctx, kmsConfig.Vault.TLSCA.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get configmap %s in openshift-config: %v", kmsConfig.Vault.TLSCA.Name, err)
		}
		if len(cm.Data) == 0 {
			return nil, fmt.Errorf("configmap %s in openshift-config has empty data", kmsConfig.Vault.TLSCA.Name)
		}
		return cm.Data, nil
	default:
		return nil, nil
	}
}
