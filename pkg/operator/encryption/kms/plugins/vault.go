package plugins

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
)

// NewVaultSidecarProvider creates a Vault sidecar provider from the given KMS plugin configuration.
func NewVaultSidecarProvider(name, keyID, udsPath string, pluginConfig *configv1.KMSPluginConfig) (*Vault, error) {
	if pluginConfig == nil {
		return nil, fmt.Errorf("plugin config cannot be nil")
	}
	return &Vault{
		name:    name,
		keyID:   keyID,
		udsPath: udsPath,
		config:  &pluginConfig.Vault,
	}, nil
}

// Vault implements SidecarProvider for HashiCorp Vault KMS.
type Vault struct {
	name    string
	keyID   string
	udsPath string
	config  *configv1.VaultKMSPluginConfig
}

// Name returns the sidecar name appended by the key id.
func (v *Vault) Name() string {
	return fmt.Sprintf("%s-%s", v.name, v.keyID)
}

// BuildSidecarContainer returns a container spec for the Vault KMS plugin sidecar
// configured with the Vault address, namespace, transit mount, and transit key.
func (v *Vault) BuildSidecarContainer() (corev1.Container, error) {
	if v.config == nil {
		return corev1.Container{}, fmt.Errorf("vault config cannot be nil")
	}
	return corev1.Container{
		Name:  v.Name(),
		Image: v.config.KMSPluginImage,
		Args: []string{
			fmt.Sprintf("-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/secret-id-%s", v.keyID),
			fmt.Sprintf("-listen-address=%s", v.udsPath),
			fmt.Sprintf("-vault-address=%s", v.config.VaultAddress),
			fmt.Sprintf("-vault-namespace=%s", v.config.VaultNamespace),
			fmt.Sprintf("-transit-mount=%s", v.config.TransitMount),
			fmt.Sprintf("-transit-key=%s", v.config.TransitKey),
		},
	}, nil
}
