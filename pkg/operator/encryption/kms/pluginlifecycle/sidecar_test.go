package pluginlifecycle

import (
	"context"
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	fake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/ptr"
)

type sidecarTestFixtures struct {
	pluginConfigBytes      []byte
	pluginConfigKey        string
	encryptionConfigBytes  []byte
	encryptionConfigSecret *corev1.Secret
	resourceDirVolume      corev1.Volume
}

func newSidecarTestFixtures(t *testing.T) sidecarTestFixtures {
	t.Helper()

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
					Secret: configv1.VaultSecretReference{Name: "vault-approle"},
				},
			},
			TLS: configv1.VaultTLSConfig{
				CABundle:   configv1.VaultConfigMapReference{Name: "vault-ca-bundle"},
				ServerName: "vault.internal.example.com",
			},
		},
	}
	pluginConfigBytes, err := encoding.EncodeKMSPluginConfig(*vaultConfig)
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

	pluginConfigKey := "kms-plugin-config-555"
	encryptionConfigSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "encryption-config",
			Namespace: "openshift-kube-apiserver",
		},
		Data: map[string][]byte{
			"encryption-config": encryptionConfigBytes,
			pluginConfigKey:     pluginConfigBytes,
			"kms-plugin-secret-vault-approle_role-id-555":            []byte("test-role-id"),
			"kms-plugin-secret-vault-approle_secret-id-555":          []byte("test-secret-id"),
			"kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555": []byte("test-ca-cert"),
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

	return sidecarTestFixtures{
		pluginConfigBytes:      pluginConfigBytes,
		pluginConfigKey:        pluginConfigKey,
		encryptionConfigBytes:  encryptionConfigBytes,
		encryptionConfigSecret: encryptionConfigSecret,
		resourceDirVolume:      resourceDirVolume,
	}
}

func TestAddKMSPluginSidecarToPodSpec(t *testing.T) {
	f := newSidecarTestFixtures(t)

	secretClient := func(objs ...runtime.Object) corev1client.SecretsGetter {
		return fake.NewClientset(objs...).CoreV1()
	}

	sidecarArgs := []string{
		"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
		"-vault-address=https://vault.example.com:8200",
		"-transit-mount=transit",
		"-transit-key=my-key",
		"-approle-role-id=test-role-id",
		"-approle-secret-id-path=/var/run/secrets/kms-plugin/kms-plugin-secret-vault-approle_secret-id-555",
		"-tls-ca-file=/var/run/secrets/kms-plugin/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555",
		"-tls-sni=vault.internal.example.com",
		"-vault-namespace=my-namespace",
		"-metrics-port=0",
	}

	expectedHealthReporter := func(sockets string) corev1.Container {
		return corev1.Container{
			Name:                     "kms-health-reporter",
			Image:                    "quay.io/test/operator:latest",
			Command:                  []string{"cluster-kube-apiserver-operator", "kms-health-reporter"},
			Args:                     []string{fmt.Sprintf("--kms-sockets=%s", sockets), "--node-name=$(NODE_NAME)"},
			ImagePullPolicy:          corev1.PullIfNotPresent,
			RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env: []corev1.EnvVar{
				{
					Name: "NODE_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
					},
				},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("32Mi"),
					corev1.ResourceCPU:    resource.MustParse("10m"),
				},
			},
			SecurityContext: &corev1.SecurityContext{
				ReadOnlyRootFilesystem:   ptr.To(true),
				AllowPrivilegeEscalation: ptr.To(false),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			VolumeMounts: []corev1.VolumeMount{{Name: "kms-plugin-socket", MountPath: "/var/run/kmsplugin", ReadOnly: true}},
		}
	}

	socketMount := corev1.VolumeMount{
		Name:      "kms-plugin-socket",
		MountPath: "/var/run/kmsplugin",
	}
	refDataMount := corev1.VolumeMount{
		Name:      "kms-plugins-data",
		MountPath: "/var/run/secrets/kms-plugin",
		ReadOnly:  true,
	}
	socketVolume := corev1.Volume{
		Name: "kms-plugin-socket",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	refDataVolume := corev1.Volume{
		Name: "kms-plugins-data",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: "encryption-config",
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
				Volumes: []corev1.Volume{f.resourceDirVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "vault-kms-plugin-555",
						Image:                    "quay.io/test/vault:v1",
						Args:                     sidecarArgs,
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
						VolumeMounts: []corev1.VolumeMount{socketMount, refDataMount},
					},
					expectedHealthReporter("unix:///var/run/kmsplugin/kms-555.sock"),
				},
				Volumes: []corev1.Volume{f.resourceDirVolume, socketVolume, refDataVolume},
			},
			secretClient:        secretClient(f.encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name: "two providers during migration: both sidecars injected in keyID order",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
				Volumes: []corev1.Volume{f.resourceDirVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:  "vault-kms-plugin-777",
						Image: "quay.io/test/vault:v2",
						Args: []string{
							"-listen-address=unix:///var/run/kmsplugin/kms-777.sock",
							"-vault-address=https://vault2.example.com:8200",
							"-transit-mount=transit2",
							"-transit-key=other-key",
							"-approle-role-id=test-role-id-777",
							"-approle-secret-id-path=/var/run/secrets/kms-plugin/kms-plugin-secret-vault-approle-2_secret-id-777",
							"-tls-ca-file=/var/run/secrets/kms-plugin/kms-plugin-configmap-vault-ca-bundle-2_ca-bundle.crt-777",
							"-vault-namespace=other-namespace",
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
						VolumeMounts: []corev1.VolumeMount{socketMount, refDataMount},
					},
					{
						Name:  "vault-kms-plugin-555",
						Image: "quay.io/test/vault:v1",
						Args: []string{
							"-listen-address=unix:///var/run/kmsplugin/kms-555.sock",
							"-vault-address=https://vault.example.com:8200",
							"-transit-mount=transit",
							"-transit-key=my-key",
							"-approle-role-id=test-role-id",
							"-approle-secret-id-path=/var/run/secrets/kms-plugin/kms-plugin-secret-vault-approle_secret-id-555",
							"-tls-ca-file=/var/run/secrets/kms-plugin/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555",
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
						VolumeMounts: []corev1.VolumeMount{socketMount, refDataMount},
					},
					expectedHealthReporter("unix:///var/run/kmsplugin/kms-777.sock,unix:///var/run/kmsplugin/kms-555.sock"),
				},
				Volumes: []corev1.Volume{f.resourceDirVolume, socketVolume, refDataVolume},
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
						Authentication: configv1.VaultAuthentication{
							Type: configv1.VaultAuthenticationTypeAppRole,
							AppRole: configv1.VaultAppRoleAuthentication{
								Secret: configv1.VaultSecretReference{Name: "vault-approle-2"},
							},
						},
						TLS: configv1.VaultTLSConfig{
							CABundle: configv1.VaultConfigMapReference{Name: "vault-ca-bundle-2"},
						},
					},
				}
				pluginConfig2Bytes, err := encoding.EncodeKMSPluginConfig(*vaultConfig2)
				require.NoError(t, err)

				pluginConfigKey2 := "kms-plugin-config-777"

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
						f.pluginConfigKey:   f.pluginConfigBytes,
						pluginConfigKey2:    pluginConfig2Bytes,
						"kms-plugin-secret-vault-approle_role-id-555":              []byte("test-role-id"),
						"kms-plugin-secret-vault-approle_secret-id-555":            []byte("test-secret-id"),
						"kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555":   []byte("test-ca-cert"),
						"kms-plugin-secret-vault-approle-2_role-id-777":            []byte("test-role-id-777"),
						"kms-plugin-secret-vault-approle-2_secret-id-777":          []byte("test-secret-id-777"),
						"kms-plugin-configmap-vault-ca-bundle-2_ca-bundle.crt-777": []byte("test-ca-cert-777"),
					},
				})
			}(),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name:                "nil pod spec",
			actualPodSpec:       nil,
			secretClient:        secretClient(f.encryptionConfigSecret),
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
			secretClient:        secretClient(f.encryptionConfigSecret),
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
			secretClient:        secretClient(f.encryptionConfigSecret),
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
			secretClient:        secretClient(f.encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil, make(chan struct{}), nil),
		},
		{
			name: "existing stale sidecar is correctly replaced",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name: "vault-kms-plugin-555",
					},
				},
				Volumes: []corev1.Volume{f.resourceDirVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "vault-kms-plugin-555",
						Image:                    "quay.io/test/vault:v1",
						Args:                     sidecarArgs,
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
						VolumeMounts: []corev1.VolumeMount{socketMount, refDataMount},
					},
					expectedHealthReporter("unix:///var/run/kmsplugin/kms-555.sock"),
				},
				Volumes: []corev1.Volume{f.resourceDirVolume, socketVolume, refDataVolume},
			},
			secretClient:        secretClient(f.encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name: "conflicting volume mount on API server container",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "kms-plugin-socket", MountPath: "/other/path"},
						},
					},
				},
				Volumes: []corev1.Volume{f.resourceDirVolume},
			},
			secretClient:        secretClient(f.encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
			wantErr:             "already has volume mount kms-plugin-socket with different settings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddKMSPluginSidecarToPodSpec(context.Background(), tt.actualPodSpec, "kube-apiserver", "openshift-kube-apiserver", "encryption-config", "cluster-kube-apiserver-operator", "quay.io/test/operator:latest", tt.secretClient, tt.featureGateAccessor)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPodSpec, tt.actualPodSpec)
		})
	}
}

func TestAddKMSPluginSidecarToPodSpecIdempotency(t *testing.T) {
	f := newSidecarTestFixtures(t)
	sc := fake.NewClientset(f.encryptionConfigSecret).CoreV1()
	fga := featuregates.NewHardcodedFeatureGateAccess(
		[]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil,
	)

	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}

	call := func() {
		t.Helper()
		err := AddKMSPluginSidecarToPodSpec(context.Background(), podSpec, "kube-apiserver", "openshift-kube-apiserver", "encryption-config", "cluster-kube-apiserver-operator", "quay.io/test/operator:latest", sc, fga)
		require.NoError(t, err)
	}

	call()
	afterFirstCall := podSpec.DeepCopy()

	call()
	require.Equal(t, afterFirstCall, podSpec)
}

func TestEnsureKMSPluginSidecarInStaticPodSpec(t *testing.T) {
	f := newSidecarTestFixtures(t)

	secretClient := func(objs ...runtime.Object) corev1client.SecretsGetter {
		return fake.NewClientset(objs...).CoreV1()
	}

	socketMount := corev1.VolumeMount{
		Name:      "kms-plugin-socket",
		MountPath: "/var/run/kmsplugin",
	}
	resourceDirMount := corev1.VolumeMount{
		Name:      "resource-dir",
		MountPath: "/etc/kubernetes/static-pod-resources",
		ReadOnly:  true,
	}
	socketVolume := corev1.Volume{
		Name: "kms-plugin-socket",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	sidecarArgs := []string{
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
	}

	expectedHealthReporter := func(sockets string) corev1.Container {
		return corev1.Container{
			Name:                     "kms-health-reporter",
			Image:                    "quay.io/test/operator:latest",
			Command:                  []string{"cluster-kube-apiserver-operator", "kms-health-reporter"},
			Args:                     []string{fmt.Sprintf("--kms-sockets=%s", sockets), "--node-name=$(NODE_NAME)", "--kubeconfig=/etc/kubernetes/static-pod-resources/configmaps/kube-apiserver-cert-syncer-kubeconfig/kubeconfig"},
			ImagePullPolicy:          corev1.PullIfNotPresent,
			RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env: []corev1.EnvVar{
				{
					Name: "NODE_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
					},
				},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("32Mi"),
					corev1.ResourceCPU:    resource.MustParse("10m"),
				},
			},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:                ptr.To(int64(0)),
				ReadOnlyRootFilesystem:   ptr.To(true),
				AllowPrivilegeEscalation: ptr.To(false),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "kms-plugin-socket", MountPath: "/var/run/kmsplugin", ReadOnly: true},
				{Name: "resource-dir", MountPath: "/etc/kubernetes/static-pod-resources", ReadOnly: true},
			},
		}
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
			name: "stale sidecar from removed provider is pruned",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:  "vault-kms-plugin-777",
						Image: "quay.io/test/vault:v2",
						Args:  []string{"-old-arg"},
					},
					{
						Name:  "vault-kms-plugin-555",
						Image: "quay.io/test/vault:v1",
						Args:  []string{"-old-arg"},
					},
					{
						Name:  "kms-health-reporter",
						Image: "quay.io/test/operator:latest",
					},
				},
				Volumes: []corev1.Volume{f.resourceDirVolume, socketVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "vault-kms-plugin-555",
						Image:                    "quay.io/test/vault:v1",
						Args:                     sidecarArgs,
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
							RunAsUser:                ptr.To(int64(0)),
							ReadOnlyRootFilesystem:   ptr.To(true),
							AllowPrivilegeEscalation: ptr.To(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
						VolumeMounts: []corev1.VolumeMount{socketMount, resourceDirMount},
					},
					expectedHealthReporter("unix:///var/run/kmsplugin/kms-555.sock"),
				},
				Volumes: []corev1.Volume{f.resourceDirVolume, socketVolume},
			},
			secretClient:        secretClient(f.encryptionConfigSecret),
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateKMSEncryption}, nil),
		},
		{
			name: "all KMS resources removed when no KMS plugins in config",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{socketMount},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:  "vault-kms-plugin-555",
						Image: "quay.io/test/vault:v1",
					},
					{
						Name:  "kms-health-reporter",
						Image: "quay.io/test/operator:latest",
					},
				},
				Volumes: []corev1.Volume{f.resourceDirVolume, socketVolume},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:         "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{},
					},
				},
				InitContainers: []corev1.Container{},
				Volumes:        []corev1.Volume{f.resourceDirVolume},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnsureKMSPluginSidecarInStaticPodSpec(context.Background(), tt.actualPodSpec, "kube-apiserver", "openshift-kube-apiserver", "encryption-config", "cluster-kube-apiserver-operator", "quay.io/test/operator:latest", tt.secretClient, tt.featureGateAccessor)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPodSpec, tt.actualPodSpec)
		})
	}
}
