package kms

import (
	"errors"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestKeyIDFromPluginConfigSecretDataKey(t *testing.T) {
	tests := []struct {
		name      string
		dataKey   string
		wantKeyID string
		wantFound bool
		wantError bool
	}{
		{
			name:      "valid key",
			dataKey:   "kms-plugin-config-1",
			wantKeyID: "1",
			wantFound: true,
		},
		{
			name:      "valid key with large ID",
			dataKey:   "kms-plugin-config-42",
			wantKeyID: "42",
			wantFound: true,
		},
		{
			name:    "encryption-config key",
			dataKey: "encryption-config",
		},
		{
			name:      "non-integer keyID",
			dataKey:   "kms-plugin-config-abc",
			wantError: true,
		},
		{
			name:    "missing keyID",
			dataKey: "kms-plugin-config-",
		},
		{
			name:    "empty string",
			dataKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, found, err := KeyIDFromPluginConfigSecretDataKey(tt.dataKey)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantFound, found)
			if found {
				require.Equal(t, tt.wantKeyID, keyID)
			}
		})
	}
}

func TestToPluginConfigSecretDataKeyFor(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantKey   string
		wantError bool
	}{
		{
			name:    "valid keyID",
			keyID:   "1",
			wantKey: "kms-plugin-config-1",
		},
		{
			name:    "valid large keyID",
			keyID:   "42",
			wantKey: "kms-plugin-config-42",
		},
		{
			name:      "non-integer keyID",
			keyID:     "abc",
			wantError: true,
		},
		{
			name:      "empty keyID",
			keyID:     "",
			wantError: true,
		},
		{
			name:      "negative keyID",
			keyID:     "-1",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToPluginConfigSecretDataKeyFor(tt.keyID)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKey, got)
		})
	}
}

func TestGetKeyIDFromPluginName(t *testing.T) {
	tests := []struct {
		name       string
		pluginName string
		wantKeyID  string
		wantErr    string
	}{
		{
			name:       "standard provider name",
			pluginName: "555_secrets",
			wantKeyID:  "555",
		},
		{
			name:       "single digit key ID",
			pluginName: "3_configmaps",
			wantKeyID:  "3",
		},
		{
			name:       "resource name with dots",
			pluginName: "42_secrets.core",
			wantKeyID:  "42",
		},
		{
			name:       "no underscore separator",
			pluginName: "noseparator",
			wantErr:    "invalid provider name",
		},
		{
			name:       "empty string",
			pluginName: "",
			wantErr:    "invalid provider name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := GetKeyIDFromPluginName(tt.pluginName)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKeyID, keyID)
		})
	}
}

func TestParsePluginConfig(t *testing.T) {
	vaultConfig := &configv1.KMSPluginConfig{
		Type: configv1.VaultKMSProvider,
		Vault: configv1.VaultKMSPluginConfig{
			KMSPluginImage: "quay.io/test/vault:v1",
			VaultAddress:   "https://vault.example.com:8200",
			VaultNamespace: "my-namespace",
			TransitKey:     "my-key",
			TransitMount:   "transit",
		},
	}
	configBytes, err := encoding.EncodeKMSPluginConfig(*vaultConfig)
	require.NoError(t, err)

	pluginConfigKey, err := ToPluginConfigSecretDataKeyFor("555")
	require.NoError(t, err)

	tests := []struct {
		name    string
		secret  *corev1.Secret
		keyID   string
		wantErr string
	}{
		{
			name: "valid plugin config",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					pluginConfigKey: configBytes,
				},
			},
			keyID: "555",
		},
		{
			name: "missing plugin config key",
			secret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			keyID:   "555",
			wantErr: "missing plugin config key",
		},
		{
			name: "invalid JSON",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					pluginConfigKey: []byte(`{invalid`),
				},
			},
			keyID:   "555",
			wantErr: "failed to decode plugin config",
		},
		{
			name: "invalid keyID",
			secret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			keyID:   "abc",
			wantErr: "failed to create plugin config secret data key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParsePluginConfig(tt.secret, tt.keyID)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, config)
			require.Equal(t, vaultConfig, config)
		})
	}
}

func TestKmsEndpointsByKeyID(t *testing.T) {
	tests := []struct {
		name    string
		config  *apiserverv1.EncryptionConfiguration
		want    map[string]string
		wantErr string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: "config cannot be nil",
		},
		{
			name: "no KMS providers",
			config: &apiserverv1.EncryptionConfiguration{
				Resources: []apiserverv1.ResourceConfiguration{
					{
						Resources: []string{"secrets"},
						Providers: []apiserverv1.ProviderConfiguration{
							{AESCBC: &apiserverv1.AESConfiguration{}},
						},
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "single KMS provider",
			config: &apiserverv1.EncryptionConfiguration{
				Resources: []apiserverv1.ResourceConfiguration{
					{
						Resources: []string{"secrets"},
						Providers: []apiserverv1.ProviderConfiguration{
							{
								KMS: &apiserverv1.KMSConfiguration{
									Name:     "555_secrets",
									Endpoint: "unix:///var/run/kmsplugin/kms-555.sock",
								},
							},
						},
					},
				},
			},
			want: map[string]string{
				"555": "unix:///var/run/kmsplugin/kms-555.sock",
			},
		},
		{
			name: "two providers during migration, same provider repeated across resource groups",
			config: &apiserverv1.EncryptionConfiguration{
				Resources: []apiserverv1.ResourceConfiguration{
					{
						Resources: []string{"secrets"},
						Providers: []apiserverv1.ProviderConfiguration{
							{
								KMS: &apiserverv1.KMSConfiguration{
									Name:     "2_secrets",
									Endpoint: "unix:///var/run/kmsplugin/kms-2.sock",
								},
							},
							{
								KMS: &apiserverv1.KMSConfiguration{
									Name:     "1_secrets",
									Endpoint: "unix:///var/run/kmsplugin/kms-1.sock",
								},
							},
						},
					},
					{
						Resources: []string{"configmaps"},
						Providers: []apiserverv1.ProviderConfiguration{
							{
								KMS: &apiserverv1.KMSConfiguration{
									Name:     "2_configmaps",
									Endpoint: "unix:///var/run/kmsplugin/kms-2.sock",
								},
							},
							{
								KMS: &apiserverv1.KMSConfiguration{
									Name:     "1_configmaps",
									Endpoint: "unix:///var/run/kmsplugin/kms-1.sock",
								},
							},
						},
					},
				},
			},
			want: map[string]string{
				"1": "unix:///var/run/kmsplugin/kms-1.sock",
				"2": "unix:///var/run/kmsplugin/kms-2.sock",
			},
		},
		{
			name: "invalid provider name format",
			config: &apiserverv1.EncryptionConfiguration{
				Resources: []apiserverv1.ResourceConfiguration{
					{
						Resources: []string{"secrets"},
						Providers: []apiserverv1.ProviderConfiguration{
							{
								KMS: &apiserverv1.KMSConfiguration{
									Name:     "noseparator",
									Endpoint: "unix:///var/run/kmsplugin/kms-1.sock",
								},
							},
						},
					},
				},
			},
			wantErr: "failed to parse key ID from provider name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KMSendpointsByKeyID(tt.config)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAddKMSPluginVolume(t *testing.T) {
	directoryOrCreate := corev1.HostPathDirectoryOrCreate

	tests := []struct {
		name                string
		featureGateAccessor featuregates.FeatureGateAccess
		actualPodSpec       *corev1.PodSpec
		expectedPodSpec     *corev1.PodSpec
		containerName       string
		expectError         bool
	}{
		{
			name: "nil pod: returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec:   nil,
			expectedPodSpec: nil,
			containerName:   "kube-apiserver",
			expectError:     true,
		},
		{
			name: "container not found: returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
				},
			},
			expectedPodSpec: nil,
			containerName:   "kube-apiserver",
			expectError:     true,
		},
		{
			name: "feature gates not observed: no volume added",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting(
				nil,
				nil,
				make(chan struct{}),
				nil,
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
		{
			name: "feature gate accessor error: returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting(
				nil,
				nil,
				func() chan struct{} { ch := make(chan struct{}); close(ch); return ch }(),
				errors.New("some error"),
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: nil,
			containerName:   "kube-apiserver",
			expectError:     true,
		},
		{
			name: "KMSEncryption feature gate disabled: no volume added",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
		{
			name: "KMSEncryption feature gate enabled: volume and mount added",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "kms-plugin-socket", MountPath: "/var/run/kmsplugin"},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "kms-plugin-socket",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/run/kmsplugin",
								Type: &directoryOrCreate,
							},
						},
					},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
		{
			name: "KMSEncryption feature gate enabled: only kube-apiserver container gets mount",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
					{Name: "kube-apiserver"},
					{Name: "another-container"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
					{
						Name: "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "kms-plugin-socket", MountPath: "/var/run/kmsplugin"},
						},
					},
					{Name: "another-container"},
				},
				Volumes: []corev1.Volume{
					{
						Name: "kms-plugin-socket",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/run/kmsplugin",
								Type: &directoryOrCreate,
							},
						},
					},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddKMSPluginVolumeAndMountToPodSpec(tt.actualPodSpec, tt.containerName, tt.featureGateAccessor)

			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPodSpec, tt.actualPodSpec)
		})
	}
}
