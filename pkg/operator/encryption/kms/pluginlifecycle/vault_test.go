package pluginlifecycle

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestVaultSidecarProvider_BuildSidecarContainer(t *testing.T) {
	tests := []struct {
		name            string
		pluginConfig    configv1.KMSPluginConfig
		containerName   string
		keyID           string
		udsPath         string
		inputPodSpec    *corev1.PodSpec
		expectedPodSpec *corev1.PodSpec
		wantErr         string
	}{
		{
			name: "builds container with correct args",
			pluginConfig: configv1.KMSPluginConfig{
				Type: configv1.VaultKMSProvider,
				Vault: configv1.VaultKMSPluginConfig{
					KMSPluginImage: "quay.io/test/vault:v2",
					VaultAddress:   "https://vault.example.com:8200",
					VaultNamespace: "my-namespace",
					TransitKey:     "my-key",
					TransitMount:   "transit",
				},
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
							"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
							"-vault-address=https://vault.example.com:8200",
							"-transit-key=my-key",
							"-approle-role-id=dummy-role-id-555",
							"-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-555",
							"-vault-namespace=my-namespace",
							"-transit-mount=transit",
						},
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("50Mi"),
								corev1.ResourceCPU:    resource.MustParse("5m"),
							},
						},
					},
				},
			},
		},
		{
			name: "appends to existing containers",
			pluginConfig: configv1.KMSPluginConfig{
				Type: configv1.VaultKMSProvider,
				Vault: configv1.VaultKMSPluginConfig{
					KMSPluginImage: "quay.io/test/vault:v2",
					VaultAddress:   "https://vault.example.com:8200",
					VaultNamespace: "my-namespace",
					TransitKey:     "my-key",
					TransitMount:   "transit",
				},
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
							"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
							"-vault-address=https://vault.example.com:8200",
							"-transit-key=my-key",
							"-approle-role-id=dummy-role-id-555",
							"-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-555",
							"-vault-namespace=my-namespace",
							"-transit-mount=transit",
						},
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("50Mi"),
								corev1.ResourceCPU:    resource.MustParse("5m"),
							},
						},
					},
				},
			},
		},
		{
			name: "empty optional fields",
			pluginConfig: configv1.KMSPluginConfig{
				Type: configv1.VaultKMSProvider,
				Vault: configv1.VaultKMSPluginConfig{
					KMSPluginImage: "quay.io/test/vault:v2",
					VaultAddress:   "https://vault.example.com:8200",
					TransitKey:     "my-key",
					VaultNamespace: "",
					TransitMount:   "",
				},
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
							"-listen-address=unix:///var/run/kmsplugin/kms.sock",
							"-vault-address=https://vault.example.com:8200",
							"-transit-key=my-key",
							"-approle-role-id=dummy-role-id-999",
							"-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-999",
							// These are not added
							// "-vault-namespace=",
							// "-transit-mount=",
						},
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("50Mi"),
								corev1.ResourceCPU:    resource.MustParse("5m"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := newVaultSidecarProvider(tt.containerName, tt.keyID, tt.udsPath, tt.pluginConfig)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			container, err := provider.BuildSidecarContainer()
			require.NoError(t, err)

			tt.inputPodSpec.Containers = append(tt.inputPodSpec.Containers, container)
			require.Equal(t, tt.expectedPodSpec, tt.inputPodSpec)
		})
	}
}
