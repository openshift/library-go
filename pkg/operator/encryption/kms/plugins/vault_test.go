package plugins

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestVaultSidecarProvider_BuildSidecarContainer(t *testing.T) {
	tests := []struct {
		name            string
		vaultConfig     *configv1.VaultKMSPluginConfig
		containerName   string
		keyID           string
		udsPath         string
		inputPodSpec    *corev1.PodSpec
		expectedPodSpec *corev1.PodSpec
		wantErr         string
	}{
		{
			name: "builds container with correct args",
			vaultConfig: &configv1.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultNamespace: "my-namespace",
				TransitKey:     "my-key",
				TransitMount:   "transit",
			},
			containerName: "kms-plugin",
			keyID:         "555",
			udsPath:       "unix:///var/run/kmsplugin/kms-555.sock",
			inputPodSpec:  &corev1.PodSpec{},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "kms-plugin-555",
						Image: "quay.io/test/vault:v2",
						Args: []string{
							"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/secret-id-555",
							"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
							"-vault-address=https://vault.example.com:8200",
							"-vault-namespace=my-namespace",
							"-transit-mount=transit",
							"-transit-key=my-key",
						},
					},
				},
			},
		},
		{
			name: "appends to existing containers",
			vaultConfig: &configv1.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultNamespace: "my-namespace",
				TransitKey:     "my-key",
				TransitMount:   "transit",
			},
			containerName: "kms-plugin",
			keyID:         "555",
			udsPath:       "unix:///var/run/kmsplugin/kms-555.sock",
			inputPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "kube-apiserver",
						Image: "registry.k8s.io/kube-apiserver:v1.30.0",
					},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "kube-apiserver",
						Image: "registry.k8s.io/kube-apiserver:v1.30.0",
					},
					{
						Name:  "kms-plugin-555",
						Image: "quay.io/test/vault:v2",
						Args: []string{
							"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/secret-id-555",
							"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
							"-vault-address=https://vault.example.com:8200",
							"-vault-namespace=my-namespace",
							"-transit-mount=transit",
							"-transit-key=my-key",
						},
					},
				},
			},
		},
		{
			name: "empty optional fields",
			vaultConfig: &configv1.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
			},
			containerName: "kms-plugin",
			keyID:         "999",
			udsPath:       "unix:///var/run/kmsplugin/kms.sock",
			inputPodSpec:  &corev1.PodSpec{},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "kms-plugin-999",
						Image: "quay.io/test/vault:v2",
						Args: []string{
							"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/secret-id-999",
							"-listen-address=unix:///var/run/kmsplugin/kms.sock",
							"-vault-address=https://vault.example.com:8200",
							"-vault-namespace=",
							"-transit-mount=",
							"-transit-key=",
						},
					},
				},
			},
		},
		{
			name:          "nil vault config",
			vaultConfig:   nil,
			containerName: "kms-plugin",
			keyID:         "1",
			udsPath:       "unix:///var/run/kmsplugin/kms.sock",
			inputPodSpec:  &corev1.PodSpec{},
			wantErr:       "vault config cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Vault{
				name:    tt.containerName,
				keyID:   tt.keyID,
				udsPath: tt.udsPath,
				config:  tt.vaultConfig,
			}

			container, err := provider.BuildSidecarContainer()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			tt.inputPodSpec.Containers = append(tt.inputPodSpec.Containers, container)
			require.Equal(t, tt.expectedPodSpec, tt.inputPodSpec)
		})
	}
}
