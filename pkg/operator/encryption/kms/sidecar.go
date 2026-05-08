package kms

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/plugins"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

type OperatorConfig struct {
	EncryptionConfigNamespace  string
	EncryptionConfigSecretName string
	APIServerContainerName     string
}

type SidecarProvider interface {
	BuildSidecarContainer(name string, kmsConfiguration *apiserverv1.KMSConfiguration) (corev1.Container, error)
}

func newSidecarProvider(providerConfig *configv1.KMSConfig, secretDataPath string) (SidecarProvider, error) {
	switch providerConfig.Type {
	case configv1.VaultKMSProvider:
		return plugins.NewVaultSidecarProvider(providerConfig, secretDataPath)
	default:
		return nil, fmt.Errorf("unsupported KMS provider configuration")
	}
}

func InjectIntoPodSpec(podSpec *corev1.PodSpec, secretLister corev1listers.SecretLister, opConfig OperatorConfig) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}

	encryptionConfigurationSecret, err := secretLister.Secrets(opConfig.EncryptionConfigNamespace).Get(opConfig.EncryptionConfigSecretName)
	if err != nil {
		klog.V(4).Infof("KMS is disabled: could not get %s secret: %v", opConfig.EncryptionConfigSecretName, err)
		return nil
	}

	encryptionConfigurationBytes, ok := encryptionConfigurationSecret.Data["encryption-config"]
	if !ok {
		klog.V(4).Infof("KMS is disabled: could not get encryption-config key in secret %s", encryptionConfigurationSecret.Name)
		return nil
	}

	encryptionConfiguration, err := encoding.DecodeEncryptionConfiguration(encryptionConfigurationBytes)
	if err != nil {
		return fmt.Errorf("failed to decode EncryptionConfiguration from %s/%s secret: %w", opConfig.EncryptionConfigNamespace, opConfig.EncryptionConfigSecretName, err)
	}

	// TODO: don't get only the first? Deduplicate and do this in a loop
	kmsConfiguration := findFirstKMSConfiguration(encryptionConfiguration)
	if kmsConfiguration == nil {
		// TODO: should error out instead?
		klog.V(4).Infof("KMS is disabled: no KMS provider found in EncryptionConfiguration")
		return nil
	}

	providerConfig, err := parseProviderConfig(encryptionConfigurationSecret, kmsConfiguration)
	if err != nil {
		return fmt.Errorf("failed to parse provider config: %w", err)
	}

	secretDataPath, err := parseSecretDataPath(kmsConfiguration)
	if err != nil {
		return fmt.Errorf("failed to parse secret data path: %w", err)
	}

	sidecarProvider, err := newSidecarProvider(providerConfig, secretDataPath)
	if err != nil {
		return fmt.Errorf("failed to create a sidecar provider: %w", err)
	}

	klog.V(4).Infof("KMS is enabled: found config, now patching pod spec")

	if err := appendContainer(podSpec, sidecarProvider, "kms-plugin", kmsConfiguration); err != nil {
		return err
	}

	if err := addSocketVolume(podSpec, "kms-plugin"); err != nil {
		return err
	}

	if err := addResourceDirMount(podSpec, "kms-plugin"); err != nil {
		return err
	}

	if err := addSocketVolume(podSpec, opConfig.APIServerContainerName); err != nil {
		return err
	}

	return nil
}

func addResourceDirMount(podSpec *corev1.PodSpec, containerName string) error {
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
