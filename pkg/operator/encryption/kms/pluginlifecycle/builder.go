package pluginlifecycle

import (
	"context"
	"fmt"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
)

// KMSPluginBuilder constructs KMS plugin pod spec contributions for injection
// into API server pods.
type KMSPluginBuilder struct {
	encryptionConfig           *encryptiondata.Config
	encryptionConfigSecretName string
	staticPod                  bool

	healthReporter *healthReporter
}

// NewKMSPluginBuilder creates a builder that defaults to deployment mode.
func NewKMSPluginBuilder() *KMSPluginBuilder {
	return &KMSPluginBuilder{}
}

// FromEncryptionConfig loads all KMS plugins from a parsed encryption config.
// The encryptionConfigSecretName identifies the Secret the config was parsed
// from; it is used for volume configuration in both deployment and static pod
// modes.
func (b *KMSPluginBuilder) FromEncryptionConfig(encryptionConfigSecretName string, cfg *encryptiondata.Config) *KMSPluginBuilder {
	b.encryptionConfigSecretName = encryptionConfigSecretName
	b.encryptionConfig = cfg
	return b
}

// AsStaticPod switches the builder to static pod mode. Sidecars will reference
// data from the resource-dir volume and run as root (UID 0).
func (b *KMSPluginBuilder) AsStaticPod() *KMSPluginBuilder {
	b.staticPod = true
	return b
}

// WithHealthReporter enables injection of a health-reporter sidecar.
// operatorBinary is the parent binary (e.g. "cluster-kube-apiserver-operator");
// when empty, the subcommand is invoked directly via the image ENTRYPOINT.
func (b *KMSPluginBuilder) WithHealthReporter(operatorBinary, operatorImage string) *KMSPluginBuilder {
	b.healthReporter = &healthReporter{
		name:           "kms-health-reporter",
		operatorBinary: operatorBinary,
		subcommand:     health.Subcommand,
		image:          operatorImage,
	}
	return b
}

// Apply mutates the given pod spec by injecting KMS plugin sidecars, volumes,
// and volume mounts. containerName identifies the API server container that
// needs the socket volume mount.
//
// It is a no-op (returns nil error) when no KMS plugins are found.
// It is idempotent.
func (b *KMSPluginBuilder) Apply(podSpec *corev1.PodSpec, containerName string) error {
	if podSpec == nil {
		return fmt.Errorf("pod spec cannot be nil")
	}
	if containerName == "" {
		return fmt.Errorf("container name cannot be empty")
	}

	kmsConfigurations, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(b.encryptionConfig)
	if err != nil {
		return fmt.Errorf("failed to get KMS configurations: %w", err)
	}
	if len(kmsConfigurations) == 0 {
		klog.V(4).Infof("skipping KMS sidecar injection: no KMS plugins found in EncryptionConfiguration")
		return nil
	}

	var refDataVolumeName, refDataMountPath, referenceDataDir string
	if b.staticPod {
		refDataVolumeName = resourceDirVolumeName
		refDataMountPath = resourcesDir
		referenceDataDir = filepath.Join(resourcesDir, "secrets", b.encryptionConfigSecretName)
	} else {
		refDataVolumeName = referenceDataVolumeName
		refDataMountPath = referenceDataMountPath
		referenceDataDir = referenceDataMountPath
	}

	klog.V(4).Infof("injecting %d KMS sidecar(s)", len(kmsConfigurations))

	socketVolumeMount := corev1.VolumeMount{Name: kmsPluginSocketVolumeName, MountPath: kmsPluginSocketMountPath, ReadOnly: false}
	refDataVolumeMount := corev1.VolumeMount{Name: refDataVolumeName, MountPath: refDataMountPath, ReadOnly: true}

	sockets := make([]string, 0, len(kmsConfigurations))
	for _, kmsConfiguration := range kmsConfigurations {
		// ExtractUniqueAndSortedKMSConfigurations function rewrites the .Name field to include only the key ID
		keyID := kmsConfiguration.Name
		sockets = append(sockets, kmsConfiguration.Endpoint)

		pluginConfig, ok := b.encryptionConfig.KMSPlugins[keyID]
		if !ok {
			return fmt.Errorf("missing plugin config for keyID %s", keyID)
		}

		refData := &referenceDataResolver{
			pluginsSecretData:    b.encryptionConfig.KMSPluginsSecretData,
			pluginsConfigMapData: b.encryptionConfig.KMSPluginsConfigMapData,
			referenceDataDir:     referenceDataDir,
			keyID:                keyID,
		}

		provider, err := newSidecarProvider(keyID, kmsConfiguration.Endpoint, pluginConfig, refData)
		if err != nil {
			return fmt.Errorf("failed to create a sidecar provider for keyID %s: %w", keyID, err)
		}

		if err := ensureSidecarContainer(podSpec, provider); err != nil {
			return err
		}

		if err := ensureVolumeMountInContainer(podSpec.InitContainers, provider.Name(), socketVolumeMount); err != nil {
			return err
		}

		if err := ensureVolumeMountInContainer(podSpec.InitContainers, provider.Name(), refDataVolumeMount); err != nil {
			return err
		}

		if b.staticPod {
			if err := setRunAsRoot(podSpec.InitContainers, provider.Name()); err != nil {
				return err
			}
		}
	}

	if err := ensureVolumeMountInContainer(podSpec.Containers, containerName, socketVolumeMount); err != nil {
		return err
	}

	if err := ensureSocketVolume(podSpec); err != nil {
		return err
	}

	if !b.staticPod {
		if err := ensureReferenceDataVolume(podSpec, b.encryptionConfigSecretName); err != nil {
			return err
		}
	}

	if err := b.applyHealthReporter(podSpec, sockets); err != nil {
		return err
	}

	return nil
}

func fetchEncryptionConfig(ctx context.Context, encryptionConfigNamespace, encryptionConfigSecretName string, secretClient corev1client.SecretsGetter) (*encryptiondata.Config, error) {
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

	if encryptionConfig == nil {
		return nil, fmt.Errorf("encryption configuration is required in %s/%s secret", encryptionConfigNamespace, encryptionConfigSecretName)
	}

	return encryptionConfig, nil
}
