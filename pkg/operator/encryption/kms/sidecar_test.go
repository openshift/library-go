package kms

import (
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/plugins"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestNewSidecarProvider(t *testing.T) {
	credentials := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-kms-credentials"},
		Data: map[string][]byte{
			"VAULT_ROLE_ID":   []byte("role-id"),
			"VAULT_SECRET_ID": []byte("secret-id"),
		},
	}

	tests := []struct {
		name    string
		config  *state.KMSProviderConfig
		wantErr string
	}{
		{
			name: "vault provider",
			config: &state.KMSProviderConfig{
				Vault: &state.VaultProviderConfig{
					Image:        "quay.io/test/vault:v1",
					VaultAddress: "https://vault.example.com:8200",
					TransitKey:   "my-key",
				},
			},
		},
		{
			name:    "unsupported provider",
			config:  &state.KMSProviderConfig{},
			wantErr: "unsupported KMS provider configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSidecarProvider(tt.config, credentials)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, provider)
		})
	}
}

func TestAppendContainer(t *testing.T) {
	credentials := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-kms-credentials"},
		Data: map[string][]byte{
			"VAULT_ROLE_ID":   []byte("role-id"),
			"VAULT_SECRET_ID": []byte("secret-id"),
		},
	}

	kmsConfig := &apiserverv1.KMSConfiguration{
		APIVersion: "v2",
		Name:       "test",
		Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
	}

	tests := []struct {
		name    string
		podSpec *corev1.PodSpec
		wantErr string
	}{
		{
			name: "sidecar container added",
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
		},
		{
			name:    "nil pod spec",
			podSpec: nil,
			wantErr: "pod spec cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &plugins.VaultSidecarProvider{
				Config: &state.VaultProviderConfig{
					Image:          "quay.io/test/vault:v1",
					VaultAddress:   "https://vault.example.com:8200",
					VaultNamespace: "ns",
					TransitKey:     "key",
					TransitMount:   "transit",
				},
				Credentials: credentials,
			}

			err := appendContainer(tt.podSpec, provider, "kms-plugin", kmsConfig)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, tt.podSpec.Containers, 2)
			require.Equal(t, "kms-plugin", tt.podSpec.Containers[1].Name)
			require.Equal(t, "quay.io/test/vault:v1", tt.podSpec.Containers[1].Image)
		})
	}
}
