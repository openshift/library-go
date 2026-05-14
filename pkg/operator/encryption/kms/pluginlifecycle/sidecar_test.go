package pluginlifecycle

import (
	"context"
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	fake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

func TestInjectIntoPodSpec(t *testing.T) {
	secretClient := func(secrets ...*corev1.Secret) corev1client.SecretsGetter {
		objs := make([]runtime.Object, len(secrets))
		for i, s := range secrets {
			objs[i] = s
		}
		return fake.NewSimpleClientset(objs...).CoreV1()
	}

	vaultConfig := &configv1.KMSPluginConfig{
		Type: configv1.VaultKMSProvider,
		Vault: configv1.VaultKMSPluginConfig{
			KMSPluginImage: "quay.io/test/vault:v1",
			VaultAddress:   "https://vault.example.com:8200",
			VaultNamespace: "my-namespace",
			TransitKey:     "my-key",
			TransitMount:   "transit",
			Authentication: configv1.VaultAuthentication{
				Type: configv1.VaultAuthenticationTypeAppRole,
				AppRole: configv1.VaultAppRoleAuthentication{
					Secret: configv1.VaultSecretReference{Name: "vault-kms-credentials"},
				},
			},
		},
	}
	pluginConfigBytes, err := encoding.EncodeKMSPluginConfig(*vaultConfig)
	require.NoError(t, err)

	pluginConfigKey, err := kms.ToPluginConfigSecretDataKeyFor("555")
	require.NoError(t, err)

	encryptionConfig := &apiserverv1.EncryptionConfiguration{
		Resources: []apiserverv1.ResourceConfiguration{
			{
				Resources: []string{"secrets"},
				Providers: []apiserverv1.ProviderConfiguration{
					{
						KMS: &apiserverv1.KMSConfiguration{
							APIVersion: "v2",
							Name:       "555_secrets",
							Endpoint:   "unix:///var/run/kmsplugin/kms-555.sock",
						},
					},
				},
			},
		},
	}
	encryptionConfigBytes, err := encoding.EncodeEncryptionConfiguration(encryptionConfig)
	require.NoError(t, err)

	encryptionConfigSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "encryption-config",
			Namespace: "openshift-kube-apiserver",
		},
		Data: map[string][]byte{
			"encryption-config": encryptionConfigBytes,
			pluginConfigKey:     pluginConfigBytes,
		},
	}

	sidecarArgs := []string{
		"-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-555",
		"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
		"-vault-address=https://vault.example.com:8200",
		"-vault-namespace=my-namespace",
		"-transit-mount=transit",
		"-transit-key=my-key",
	}

	socketMount := corev1.VolumeMount{
		Name:      "kms-plugin-socket",
		MountPath: "/var/run/kmsplugin",
	}
	socketVolume := corev1.Volume{
		Name: "kms-plugin-socket",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	resourceDirVolume := corev1.Volume{
		Name: "resource-dir",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/etc/kubernetes/static-pod-resources",
			},
		},
	}

	tests := []struct {
		name                string
		actualPodSpec       *corev1.PodSpec
		expectedPodSpec     *corev1.PodSpec
		secretClient        corev1client.SecretsGetter
		featureGateAccessor featuregates.FeatureGateAccess
		wantErr             string
	}{
		{
			name: "single provider: sidecar and volumes injected",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
				Volumes: []corev1.Volume{resourceDirVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
					{
						Name:         "vault-kms-plugin-555",
						Image:        "quay.io/test/vault:v1",
						Args:         sidecarArgs,
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				Volumes: []corev1.Volume{resourceDirVolume, socketVolume},
			},
			secretClient:        secretClient(encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name: "two providers during migration: both sidecars injected in keyID order",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
				Volumes: []corev1.Volume{resourceDirVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
					{
						Name:  "vault-kms-plugin-777",
						Image: "quay.io/test/vault:v2",
						Args: []string{
							"-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-777",
							"-listen-address=unix:///var/run/kmsplugin/kms-777.sock",
							"-vault-address=https://vault2.example.com:8200",
							"-vault-namespace=other-namespace",
							"-transit-mount=transit2",
							"-transit-key=other-key",
						},
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
					{
						Name:  "vault-kms-plugin-555",
						Image: "quay.io/test/vault:v1",
						Args: []string{
							"-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-555",
							"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
							"-vault-address=https://vault.example.com:8200",
							"-vault-namespace=my-namespace",
							"-transit-mount=transit",
							"-transit-key=my-key",
						},
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				Volumes: []corev1.Volume{resourceDirVolume, socketVolume},
			},
			secretClient: func() corev1client.SecretsGetter {
				vaultConfig2 := &configv1.KMSPluginConfig{
					Type: configv1.VaultKMSProvider,
					Vault: configv1.VaultKMSPluginConfig{
						KMSPluginImage: "quay.io/test/vault:v2",
						VaultAddress:   "https://vault2.example.com:8200",
						VaultNamespace: "other-namespace",
						TransitKey:     "other-key",
						TransitMount:   "transit2",
					},
				}
				pluginConfig2Bytes, err := encoding.EncodeKMSPluginConfig(*vaultConfig2)
				require.NoError(t, err)

				pluginConfigKey2, err := kms.ToPluginConfigSecretDataKeyFor("777")
				require.NoError(t, err)

				multiEncConfig := &apiserverv1.EncryptionConfiguration{
					Resources: []apiserverv1.ResourceConfiguration{
						{
							Resources: []string{"secrets"},
							Providers: []apiserverv1.ProviderConfiguration{
								{
									KMS: &apiserverv1.KMSConfiguration{
										APIVersion: "v2",
										Name:       "555_secrets",
										Endpoint:   "unix:///var/run/kmsplugin/kms-555.sock",
									},
								},
								{
									KMS: &apiserverv1.KMSConfiguration{
										APIVersion: "v2",
										Name:       "777_secrets",
										Endpoint:   "unix:///var/run/kmsplugin/kms-777.sock",
									},
								},
							},
						},
					},
				}
				multiEncConfigBytes, err := encoding.EncodeEncryptionConfiguration(multiEncConfig)
				require.NoError(t, err)

				return secretClient(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "encryption-config",
						Namespace: "openshift-kube-apiserver",
					},
					Data: map[string][]byte{
						"encryption-config": multiEncConfigBytes,
						pluginConfigKey:     pluginConfigBytes,
						pluginConfigKey2:    pluginConfig2Bytes,
					},
				})
			}(),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name:                "nil pod spec",
			actualPodSpec:       nil,
			secretClient:        secretClient(encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
			wantErr:             "pod spec cannot be nil",
		},
		{
			name: "missing encryption-config secret: pod spec unchanged",
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
			secretClient:        secretClient(),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name: "missing encryption-config key in secret: pod spec unchanged",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			secretClient: secretClient(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "encryption-config",
					Namespace: "openshift-kube-apiserver",
				},
				Data: map[string][]byte{"other-key": []byte("data")},
			}),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
			wantErr:             "encryption configuration is required",
		},
		{
			name: "no KMS plugin in EncryptionConfiguration: pod spec unchanged",
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
			secretClient: func() corev1client.SecretsGetter {
				noKMSConfig := &apiserverv1.EncryptionConfiguration{
					Resources: []apiserverv1.ResourceConfiguration{
						{
							Resources: []string{"secrets"},
							Providers: []apiserverv1.ProviderConfiguration{
								{AESCBC: &apiserverv1.AESConfiguration{}},
							},
						},
					},
				}
				noKMSBytes, err := encoding.EncodeEncryptionConfiguration(noKMSConfig)
				require.NoError(t, err)
				return secretClient(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "encryption-config",
						Namespace: "openshift-kube-apiserver",
					},
					Data: map[string][]byte{"encryption-config": noKMSBytes},
				})
			}(),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name: "missing API server container",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
				},
			},
			secretClient:        secretClient(encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
			wantErr:             fmt.Sprintf("container %s not found", "kube-apiserver"),
		},
		{
			name: "feature gate disabled: pod spec unchanged",
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
			secretClient:        secretClient(encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateKMSEncryption}),
		},
		{
			name: "feature gates not yet observed: pod spec unchanged",
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
			secretClient:        secretClient(encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil, make(chan struct{}), nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddKMSPluginSidecarToPodSpec(context.Background(), tt.actualPodSpec, "kube-apiserver", "openshift-kube-apiserver", "encryption-config", tt.secretClient, tt.featureGateAccessor)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPodSpec, tt.actualPodSpec)
		})
	}
}
