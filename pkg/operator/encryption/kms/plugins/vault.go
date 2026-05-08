package plugins

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/utils/ptr"
)

type VaultSidecarProvider struct {
	Config         *configv1.VaultKMSConfig
	SecretDataPath string
}

func NewVaultSidecarProvider(providerConfig *configv1.KMSConfig, secretDataPath string) (*VaultSidecarProvider, error) {
	return &VaultSidecarProvider{
		Config:         &providerConfig.Vault,
		SecretDataPath: secretDataPath,
	}, nil
}

func (v *VaultSidecarProvider) BuildSidecarContainer(name string, kmsConfig *apiserverv1.KMSConfiguration) (corev1.Container, error) {
	if v.Config == nil {
		return corev1.Container{}, fmt.Errorf("vault config cannot be nil")
	}

	// FIXME: this is fragile. TBD
	args := fmt.Sprintf(`set -e
	CREDS=$(cat %s)
	SECRET_ID=${CREDS#*\"VAULT_SECRET_ID\":\"}
	SECRET_ID=${SECRET_ID%%%%\"*}
	ROLE_ID=${CREDS#*\"VAULT_ROLE_ID\":\"}
	ROLE_ID=${ROLE_ID%%%%\"*}
	printf '%%s' "$SECRET_ID" > /tmp/secret-id
	exec /vault-kube-kms \
	-listen-address=%s \
	-vault-address=%s \
	-vault-namespace=%s \
	-transit-mount=%s \
	-transit-key=%s \
	-approle-role-id=$ROLE_ID \
	-approle-secret-id-path=/tmp/secret-id`,
		v.SecretDataPath,
		kmsConfig.Endpoint,
		v.Config.VaultAddress,
		v.Config.VaultNamespace,
		v.Config.TransitMount,
		v.Config.TransitKey,
	)

	return corev1.Container{
		Name:    name,
		Image:   v.Config.KMSPluginImage,
		Command: []string{"/bin/sh", "-c"},
		Args:    []string{args},
		// This is necessary to read the secret data in /etc/kubernetes/static-pod-resources/secrets/encryption-config
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: ptr.To(int64(0)),
		},
	}, nil
}
