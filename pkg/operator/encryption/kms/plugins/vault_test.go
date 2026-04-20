package plugins

import (
	"fmt"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestVaultSidecarProvider_BuildSidecarContainer(t *testing.T) {
	tests := []struct {
		name          string
		vaultConfig   *state.VaultProviderConfig
		credentials   *corev1.Secret
		containerName string
		kmsConfig     *apiserverv1.KMSConfiguration
		wantErr       string
	}{
		{
			name: "builds container with correct args",
			vaultConfig: &state.VaultProviderConfig{
				Image:          "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultNamespace: "my-namespace",
				TransitKey:     "my-key",
				TransitMount:   "transit",
			},
			credentials: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-kms-credentials"},
				Data: map[string][]byte{
					"VAULT_ROLE_ID":   []byte("test-role-id"),
					"VAULT_SECRET_ID": []byte("test-secret-id"),
				},
			},
			containerName: "kms-plugin",
			kmsConfig: &apiserverv1.KMSConfiguration{
				APIVersion: "v2",
				Name:       "555_secrets",
				Endpoint:   "unix:///var/run/kmsplugin/kms-555.sock",
			},
		},
		{
			name:        "nil vault config",
			vaultConfig: nil,
			credentials: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-kms-credentials"},
				Data:       map[string][]byte{},
			},
			containerName: "kms-plugin",
			kmsConfig:     &apiserverv1.KMSConfiguration{},
			wantErr:       "vault config cannot be nil",
		},
		{
			name: "nil credentials",
			vaultConfig: &state.VaultProviderConfig{
				Image:        "quay.io/test/vault:v2",
				VaultAddress: "https://vault.example.com:8200",
			},
			credentials:   nil,
			containerName: "kms-plugin",
			kmsConfig:     &apiserverv1.KMSConfiguration{},
			wantErr:       "vault credentials cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &VaultSidecarProvider{
				Config:      tt.vaultConfig,
				Credentials: tt.credentials,
			}

			container, err := provider.BuildSidecarContainer(tt.containerName, tt.kmsConfig)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.containerName, container.Name)
			require.Equal(t, tt.vaultConfig.Image, container.Image)
			require.Equal(t, []string{"/bin/sh", "-c"}, container.Command)

			expectedArgs := fmt.Sprintf(`
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
				tt.credentials.Data["VAULT_SECRET_ID"],
				tt.kmsConfig.Endpoint,
				tt.vaultConfig.VaultAddress,
				tt.vaultConfig.VaultNamespace,
				tt.vaultConfig.TransitMount,
				tt.vaultConfig.TransitKey,
				tt.credentials.Data["VAULT_ROLE_ID"],
			)
			require.Len(t, container.Args, 1)
			require.Equal(t, expectedArgs, container.Args[0])
		})
	}
}
