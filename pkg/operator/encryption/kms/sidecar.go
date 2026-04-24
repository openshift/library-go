package kms

import (
	"fmt"

	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/plugins"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

type OperatorConfig struct {
	EncryptionConfigNamespace  string
	EncryptionConfigSecretName string
	CredentialsNamespace       string
	CredentialsSecretName      string
	APIServerContainerName     string
}

type SidecarProvider interface {
	BuildSidecarContainer(containerName string, kmsConfig *apiserverv1.KMSConfiguration) (corev1.Container, error)
}

func NewSidecarProvider(config *state.KMSProviderConfig, credentials *corev1.Secret) (SidecarProvider, error) {
	switch {
	case config.Vault != nil:
		return &plugins.VaultSidecarProvider{
			Config: config.Vault,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported KMS provider configuration")
	}
}

func InjectIntoPodSpec(podSpec *corev1.PodSpec, featureGateAccessor featuregates.FeatureGateAccess, secretLister corev1listers.SecretLister, opConfig OperatorConfig) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	if !featureGateAccessor.AreInitialFeatureGatesObserved() {
		return nil
	}

	fg, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return fmt.Errorf("failed to get feature gates: %w", err)
	}

	if !fg.Enabled(features.FeatureGateKMSEncryption) {
		klog.Infof("KMS is disabled: feature gate %s is disabled", features.FeatureGateKMSEncryption)
		return nil
	}

	encryptionConfig, err := secretLister.Secrets(opConfig.EncryptionConfigNamespace).Get(opConfig.EncryptionConfigSecretName)
	if err != nil {
		klog.Infof("KMS is disabled: failed to get %s secret: %v", opConfig.EncryptionConfigSecretName, err)
		return nil
	}

	encryptionConfigBytes, ok := encryptionConfig.Data["encryption-config"]
	if !ok {
		klog.Infof("KMS is disabled: failed to get encryption-config key in secret")
		return nil
	}

	config, err := DecodeEncryptionConfiguration(encryptionConfigBytes)
	if err != nil {
		return fmt.Errorf("KMS is disabled: %w", err)
	}

	kmsConfig := findFirstKMSProvider(config)
	if kmsConfig == nil {
		klog.Infof("KMS is disabled: no KMS provider found in EncryptionConfiguration")
		return nil
	}

	keyID, err := ParseKeyIDFromEndpoint(kmsConfig.Endpoint)
	if err != nil {
		return err
	}

	providerConfig, err := GetKMSProviderConfig(encryptionConfig.Data, keyID)
	if err != nil {
		return err
	}

	if providerConfig.Vault == nil {
		return fmt.Errorf("only Vault KMS provider is supported")
	}

	credentials, err := secretLister.Secrets(opConfig.CredentialsNamespace).Get(opConfig.CredentialsSecretName)
	if err != nil {
		klog.Infof("KMS is disabled: failed to get %s secret: %v", opConfig.CredentialsSecretName, err)
		return nil
	}

	klog.Infof("KMS is enabled: found config, now patching pod spec")

	provider := &plugins.VaultSidecarProvider{
		Config:      providerConfig.Vault,
		Credentials: credentials,
	}

	if err := appendContainer(podSpec, provider, "kms-plugin", kmsConfig); err != nil {
		return err
	}

	if err := addSocketVolume(podSpec, "kms-plugin"); err != nil {
		return err
	}

	if err := addSocketVolume(podSpec, opConfig.APIServerContainerName); err != nil {
		return err
	}

	return nil
}

func findFirstKMSProvider(config *apiserverv1.EncryptionConfiguration) *apiserverv1.KMSConfiguration {
	for _, resource := range config.Resources {
		for _, provider := range resource.Providers {
			if provider.KMS != nil {
				return provider.KMS
			}
		}
	}
	return nil
}

func appendContainer(podSpec *corev1.PodSpec, provider SidecarProvider, containerName string, kmsConfig *apiserverv1.KMSConfiguration) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	container, err := provider.BuildSidecarContainer(containerName, kmsConfig)
	if err != nil {
		return fmt.Errorf("failed to build sidecar container: %w", err)
	}

	podSpec.Containers = append(podSpec.Containers, container)
	return nil
}

func addSocketVolume(podSpec *corev1.PodSpec, containerName string) error {
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

	foundVolumeInContainer := false
	for _, volume := range podSpec.Volumes {
		if volume.Name == "kms-plugin-socket" {
			foundVolumeInContainer = true
			break
		}
	}

	if !foundVolumeInContainer {
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
