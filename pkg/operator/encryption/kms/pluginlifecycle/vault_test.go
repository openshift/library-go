package pluginlifecycle

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

func newVaultAppRoleSecretData(t *testing.T, roleID, secretID string) state.KMSReferenceData {
	t.Helper()
	var sd state.KMSReferenceData
	require.NoError(t, sd.Set("vault-approle", "role-id", []byte(roleID)))
	require.NoError(t, sd.Set("vault-approle", "secret-id", []byte(secretID)))
	return sd
}

func newVaultCABundleConfigMapData(t *testing.T, caBundleCrt string) state.KMSReferenceData {
	t.Helper()
	var cd state.KMSReferenceData
	require.NoError(t, cd.Set("vault-ca-bundle", "ca-bundle.crt", []byte(caBundleCrt)))
	return cd
}

func TestVaultSidecarProvider_BuildSidecarContainer(t *testing.T) {
	tests := []struct {
		name               string
		vaultConfig        configv1.VaultKMSPluginConfig
		secretData         state.KMSReferenceData
		configMapData      state.KMSReferenceData
		referenceDataDir   string
		containerName      string
		keyID              string
		udsPath            string
		inputContainers    []corev1.Container
		expectedContainers []corev1.Container
		expectErr          string
	}{
		{
			name: "builds container with correct args",
			vaultConfig: configv1.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultNamespace: "my-namespace",
				TransitKey:     "my-key",
				TransitMount:   "transit",
				Authentication: configv1.VaultAuthentication{
					AppRole: configv1.VaultAppRoleAuthentication{
						Secret: configv1.VaultSecretReference{Name: "vault-approle"},
					},
				},
				TLS: configv1.VaultTLSConfig{
					CABundle:   configv1.VaultConfigMapReference{Name: "vault-ca-bundle"},
					ServerName: "vault.internal.example.com",
				},
			},
			secretData:       newVaultAppRoleSecretData(t, "test-role-id", "test-secret-id"),
			configMapData:    newVaultCABundleConfigMapData(t, "test-ca-cert"),
			referenceDataDir: "/etc/kubernetes/static-pod-resources/secrets/encryption-config",
			containerName:    "kms-plugin",
			keyID:            "555",
			udsPath:          "unix:///var/run/kmsplugin/kms-555.sock",
			inputContainers:  nil,
			expectedContainers: []corev1.Container{
				{
					Name:  "kms-plugin-555",
					Image: "quay.io/test/vault:v2",
					Args: []string{
						"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
						"-vault-address=https://vault.example.com:8200",
						"-transit-mount=transit",
						"-transit-key=my-key",
						"-approle-role-id=test-role-id",
						"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-secret-vault-approle_secret-id-555",
						"-tls-ca-file=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555",
						"-tls-sni=vault.internal.example.com",
						"-vault-namespace=my-namespace",
						"-metrics-port=0",
					},
					ImagePullPolicy:          corev1.PullIfNotPresent,
					RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("64Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
					SecurityContext: &corev1.SecurityContext{
						ReadOnlyRootFilesystem:   ptr.To(true),
						AllowPrivilegeEscalation: ptr.To(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
				},
			},
		},
		{
			name: "appends to existing containers",
			vaultConfig: configv1.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultNamespace: "my-namespace",
				TransitKey:     "my-key",
				TransitMount:   "transit",
				Authentication: configv1.VaultAuthentication{
					AppRole: configv1.VaultAppRoleAuthentication{
						Secret: configv1.VaultSecretReference{Name: "vault-approle"},
					},
				},
				TLS: configv1.VaultTLSConfig{
					CABundle: configv1.VaultConfigMapReference{Name: "vault-ca-bundle"},
				},
			},
			secretData:       newVaultAppRoleSecretData(t, "test-role-id", "test-secret-id"),
			configMapData:    newVaultCABundleConfigMapData(t, "test-ca-cert"),
			referenceDataDir: "/etc/kubernetes/static-pod-resources/secrets/encryption-config",
			containerName:    "kms-plugin",
			keyID:            "555",
			udsPath:          "unix:///var/run/kmsplugin/kms-555.sock",
			inputContainers: []corev1.Container{
				{
					Name:  "kube-apiserver",
					Image: "registry.k8s.io/kube-apiserver:v1.30.0",
				},
			},
			expectedContainers: []corev1.Container{
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
						"-transit-mount=transit",
						"-transit-key=my-key",
						"-approle-role-id=test-role-id",
						"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-secret-vault-approle_secret-id-555",
						"-tls-ca-file=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555",
						"-vault-namespace=my-namespace",
						"-metrics-port=0",
					},
					ImagePullPolicy:          corev1.PullIfNotPresent,
					RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("64Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
					SecurityContext: &corev1.SecurityContext{
						ReadOnlyRootFilesystem:   ptr.To(true),
						AllowPrivilegeEscalation: ptr.To(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
				},
			},
		},
		{
			name: "empty optional fields",
			vaultConfig: configv1.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				TransitKey:     "my-key",
				TransitMount:   "transit",
				VaultNamespace: "",
				Authentication: configv1.VaultAuthentication{
					AppRole: configv1.VaultAppRoleAuthentication{
						Secret: configv1.VaultSecretReference{Name: "vault-approle"},
					},
				},
			},
			secretData:       newVaultAppRoleSecretData(t, "test-role-id-999", "test-secret-id-999"),
			referenceDataDir: "/var/run/secrets/kms-plugin",
			containerName:    "kms-plugin",
			keyID:            "999",
			udsPath:          "unix:///var/run/kmsplugin/kms.sock",
			inputContainers:  nil,
			expectedContainers: []corev1.Container{
				{
					Name:  "kms-plugin-999",
					Image: "quay.io/test/vault:v2",
					Args: []string{
						"-listen-address=unix:///var/run/kmsplugin/kms.sock",
						"-vault-address=https://vault.example.com:8200",
						"-transit-mount=transit",
						"-transit-key=my-key",
						"-approle-role-id=test-role-id-999",
						"-approle-secret-id-path=/var/run/secrets/kms-plugin/kms-plugin-secret-vault-approle_secret-id-999",
						"-metrics-port=0",
					},
					ImagePullPolicy:          corev1.PullIfNotPresent,
					RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("64Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
					SecurityContext: &corev1.SecurityContext{
						ReadOnlyRootFilesystem:   ptr.To(true),
						AllowPrivilegeEscalation: ptr.To(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
				},
			},
		},
		{
			name: "empty secret name",
			vaultConfig: configv1.VaultKMSPluginConfig{
				Authentication: configv1.VaultAuthentication{
					AppRole: configv1.VaultAppRoleAuthentication{
						Secret: configv1.VaultSecretReference{Name: ""},
					},
				},
			},
			containerName: "kms-plugin",
			keyID:         "555",
			udsPath:       "unix:///var/run/kmsplugin/kms-555.sock",
			expectErr:     "vault AppRole authentication secret name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pluginsSecretData encryptiondata.KMSPluginsReferenceData
			for rawKey, value := range tt.secretData.FlatEntries() {
				err := pluginsSecretData.SetFromRawKey(tt.keyID, rawKey, value)
				require.NoError(t, err)
			}

			var pluginsConfigMapData encryptiondata.KMSPluginsReferenceData
			for rawKey, value := range tt.configMapData.FlatEntries() {
				err := pluginsConfigMapData.SetFromRawKey(tt.keyID, rawKey, value)
				require.NoError(t, err)
			}

			refData := &referenceDataResolver{
				pluginsSecretData:    pluginsSecretData,
				pluginsConfigMapData: pluginsConfigMapData,
				referenceDataDir:     tt.referenceDataDir,
				keyID:                tt.keyID,
			}

			provider, err := newVaultSidecarProvider(tt.containerName, tt.keyID, tt.udsPath, tt.vaultConfig, refData)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)

			container, err := provider.BuildSidecarContainer()
			require.NoError(t, err)

			tt.inputContainers = append(tt.inputContainers, container)
			require.Equal(t, tt.expectedContainers, tt.inputContainers)
		})
	}
}
