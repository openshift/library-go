package pluginlifecycle

import (
	"context"
	"fmt"
	"path/filepath"

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
func AddKMSPluginSidecarToStaticPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
	// The static pod revision controller copies secret data to disk under resourcesDir/secrets/<secretName>/.
	referenceDataDir := filepath.Join(resourcesDir, "secrets", encryptionConfigSecretName)

	sidecarNames, err := addKMSPluginSidecars(ctx, podSpec, containerName, encryptionConfigNamespace, encryptionConfigSecretName, secretClient, featureGateAccessor, referenceDataDir)
	if err != nil {
		return err
	}

	// Don't touch the pod spec further when there are no sidecars.
	if len(sidecarNames) == 0 {
		return nil
	}

	for _, name := range sidecarNames {
		volumeMount := corev1.VolumeMount{Name: resourceDirVolumeName, MountPath: resourcesDir, ReadOnly: true}
		if err := ensureVolumeMountInContainer(podSpec.InitContainers, name, volumeMount); err != nil {
			return err
		}
		// The resource-dir files are owned by root, so the sidecar needs root to read files in that directory.
		if err := setRunAsUser(podSpec.InitContainers, name, 0); err != nil {
			return err
		}
	}

	return nil
}

// AddKMSPluginSidecarToPodSpec injects KMS plugin sidecar containers into an aggregated API server pod spec (e.g., openshift-apiserver, oauth-apiserver).
//
// It is a no-op when the KMSEncryption feature gate is not enabled or the encryption-config secret does not exist.
// The secretClient should be uncached to avoid injecting sidecars based on a stale encryption configuration.
func AddKMSPluginSidecarToPodSpec(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess) error {
	sidecarNames, err := addKMSPluginSidecars(ctx, podSpec, containerName, encryptionConfigNamespace, encryptionConfigSecretName, secretClient, featureGateAccessor, referenceDataMountPath)
	if err != nil {
		return err
	}

	// Don't touch the pod spec further when there are no sidecars.
	if len(sidecarNames) == 0 {
		return nil
	}

	for _, name := range sidecarNames {
		volumeMount := corev1.VolumeMount{Name: referenceDataVolumeName, MountPath: referenceDataMountPath, ReadOnly: true}
		if err := ensureVolumeMountInContainer(podSpec.InitContainers, name, volumeMount); err != nil {
			return err
		}
	}

	// Unlike static pods, aggregated API servers access credentials by mounting the encryption-config Secret directly as a volume.
	// Callers include the revision number in encryptionConfigSecretName (e.g. "encryption-config-7"), so each revision maps to a distinct Secret and volume.
	if err := ensureReferenceDataVolume(podSpec, encryptionConfigSecretName); err != nil {
		return err
	}

	return nil
}

// addKMSPluginSidecars contains the shared logic for discovering KMS plugins and injecting sidecar containers.
// It returns the names of the sidecar containers that were injected, so callers can add deployment-mode-specific volume mounts.
func addKMSPluginSidecars(ctx context.Context, podSpec *corev1.PodSpec, containerName string, encryptionConfigNamespace string, encryptionConfigSecretName string, secretClient corev1client.SecretsGetter, featureGateAccessor featuregates.FeatureGateAccess, referenceDataDir string) ([]string, error) {
	if podSpec == nil {
		return nil, fmt.Errorf("pod spec cannot be nil")
	}

	if containerName == "" {
		return nil, fmt.Errorf("container name cannot be empty")
	}

	if !featureGateAccessor.AreInitialFeatureGatesObserved() {
		return nil, nil
	}

	featureGates, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return nil, fmt.Errorf("failed to get feature gates: %w", err)
	}

	if !featureGates.Enabled(features.FeatureGateKMSEncryption) {
		return nil, nil
	}

	encryptionConfigurationSecret, err := secretClient.Secrets(encryptionConfigNamespace).Get(ctx, encryptionConfigSecretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		klog.V(4).Infof("skipping KMS sidecar injection: %s/%s secret not found", encryptionConfigNamespace, encryptionConfigSecretName)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get %s/%s secret: %w", encryptionConfigNamespace, encryptionConfigSecretName, err)
	}

	encryptionConfig, err := encryptiondata.FromSecret(encryptionConfigurationSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to extract encryption config from %s/%s secret: %w", encryptionConfigNamespace, encryptionConfigSecretName, err)
	}

	kmsConfigurations, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(encryptionConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS configurations: %w", err)
	}
	if len(kmsConfigurations) == 0 {
		klog.V(4).Infof("skipping KMS sidecar injection: no KMS plugins found in EncryptionConfiguration")
		return nil, nil
	}

	klog.V(4).Infof("injecting %d KMS sidecar(s)", len(kmsConfigurations))

	var sidecarNames []string
	socketVolumeMount := corev1.VolumeMount{Name: kmsPluginSocketVolumeName, MountPath: kmsPluginSocketMountPath, ReadOnly: false}
	for _, kmsConfiguration := range kmsConfigurations {
		// ExtractUniqueAndSortedKMSConfigurations function rewrites the .Name field to include only the key ID
		keyID := kmsConfiguration.Name
		udsPath := kmsConfiguration.Endpoint

		pluginConfig, ok := encryptionConfig.KMSPlugins[keyID]
		if !ok {
			return nil, fmt.Errorf("missing plugin config for keyID %s", keyID)
		}

		refData := &referenceDataResolver{
			pluginsConfigMapData: encryptionConfig.KMSPluginsConfigMapData,
			pluginsSecretData:    encryptionConfig.KMSPluginsSecretData,
			referenceDataDir:     referenceDataDir,
			keyID:                keyID,
		}

		provider, err := newSidecarProvider(keyID, udsPath, pluginConfig, refData)
		if err != nil {
			return nil, fmt.Errorf("failed to create a sidecar provider for keyID %s: %w", keyID, err)
		}

		if err := ensureSidecarContainer(podSpec, provider); err != nil {
			return nil, err
		}

		if err := ensureVolumeMountInContainer(podSpec.InitContainers, provider.Name(), socketVolumeMount); err != nil {
			return nil, err
		}

		sidecarNames = append(sidecarNames, provider.Name())
	}

	if err := ensureVolumeMountInContainer(podSpec.Containers, containerName, socketVolumeMount); err != nil {
		return nil, err
	}

	// The volume mount in the kube-apiserver and KMS plugin containers requires a volume in the podSpec
	if err := ensureSocketVolume(podSpec); err != nil {
		return nil, err
	}

	return sidecarNames, nil
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

func setRunAsUser(containers []corev1.Container, containerName string, uid int64) error {
	for i, c := range containers {
		if c.Name == containerName {
			if c.SecurityContext == nil {
				containers[i].SecurityContext = &corev1.SecurityContext{}
			}
			containers[i].SecurityContext.RunAsUser = ptr.To(uid)
			return nil
		}
	}
	return fmt.Errorf("container %s not found", containerName)
}
