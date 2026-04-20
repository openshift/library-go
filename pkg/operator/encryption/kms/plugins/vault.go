package plugins

import (
	"fmt"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

type VaultSidecarProvider struct {
	Config *state.VaultProviderConfig
	// TODO: this is temporary. The credentialls will be in a key in the encryption-configuration secret
	Credentials *corev1.Secret
}

func (v *VaultSidecarProvider) BuildSidecarContainer(containerName string, kmsConfig *apiserverv1.KMSConfiguration) (corev1.Container, error) {
	if v.Config == nil {
		return corev1.Container{}, fmt.Errorf("vault config cannot be nil")
	}
	if v.Credentials == nil {
		return corev1.Container{}, fmt.Errorf("vault credentials cannot be nil")
	}

	args := fmt.Sprintf(`
	echo "%s" > /tmp/secret-id
	exec /vault-kube-kms \
	-listen-address=%s \
	-vault-address=%s \
	-vault-namespace=%s \
	-transit-mount=%s \
	-transit-key=%s \
	-log-level=debug-extended \
	-approle-role-id=%s \
	-approle-secret-id-path=/tmp/secret-id`,
		v.Credentials.Data["VAULT_SECRET_ID"],
		kmsConfig.Endpoint,
		v.Config.VaultAddress,
		v.Config.VaultNamespace,
		v.Config.TransitMount,
		v.Config.TransitKey,
		v.Credentials.Data["VAULT_ROLE_ID"],
	)

	return corev1.Container{
		Name:    containerName,
		Image:   v.Config.Image,
		Command: []string{"/bin/sh", "-c"},
		Args:    []string{args},
	}, nil
}
