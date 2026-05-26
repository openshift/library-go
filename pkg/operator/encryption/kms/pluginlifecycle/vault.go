package pluginlifecycle

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

// newVaultSidecarProvider creates a Vault sidecar provider from the given KMS plugin configuration.
func newVaultSidecarProvider(name, keyID, udsPath string, pluginConfig configv1.KMSPluginConfig) (*vault, error) {
	return &vault{
		name:    name,
		keyID:   keyID,
		udsPath: udsPath,
		config:  &pluginConfig.Vault,
	}, nil
}

// vault implements SidecarProvider for HashiCorp Vault KMS.
type vault struct {
	name    string
	keyID   string
	udsPath string
	config  *configv1.VaultKMSPluginConfig
}

// Name returns the sidecar name appended by the key id.
func (v *vault) Name() string {
	return fmt.Sprintf("%s-%s", v.name, v.keyID)
}

// BuildSidecarContainer returns a container spec for the Vault KMS plugin sidecar
// configured with the Vault address, namespace, transit mount, and transit key.
func (v *vault) BuildSidecarContainer() (corev1.Container, error) {
	// Required API fields: always set.
	args := []string{
		fmt.Sprintf("-listen-address=%s", v.udsPath),
		fmt.Sprintf("-vault-address=%s", v.config.VaultAddress),
		fmt.Sprintf("-transit-mount=%s", v.config.TransitMount),
		fmt.Sprintf("-transit-key=%s", v.config.TransitKey),
		// TODO(bertinatto): dummy value for the Vault mock plugin; will come from the encryption-config secret.
		fmt.Sprintf("-approle-role-id=dummy-role-id-%s", v.keyID),
		// TODO(bertinatto): placeholder path for the Vault mock plugin; will differ per operator (KASO vs. aggregated apiserver operators).
		fmt.Sprintf("-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-%s", v.keyID),
	}

	// Optional fields: only pass non-empty values.
	if v.config.VaultNamespace != "" {
		args = append(args, fmt.Sprintf("-vault-namespace=%s", v.config.VaultNamespace))
	}

	return corev1.Container{
		Name:            v.Name(),
		Image:           v.config.KMSPluginImage,
		Args:            args,
		ImagePullPolicy: corev1.PullIfNotPresent,
		// We place the container in InitContainers with RestartPolicyAlways so the kubelet starts it before
		// regular containers and keeps it running for the pod's lifetime.
		RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		// TODO(bertinatto): the plugin sidecar needs to be measure under heavy load to figure out good defaults.
		// For now follow what most sidecars in the kube-apiserver pod do. xref:
		// https://github.com/openshift/cluster-kube-apiserver-operator/commit/e15a19cd2474c8b60ce17ac16dd8f422c729847a
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("50Mi"),
				corev1.ResourceCPU:    resource.MustParse("5m"),
			},
		},
	}, nil
}
