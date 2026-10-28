package pluginlifecycle

import (
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
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
		vaultConfig        kms.VaultKMSPluginConfig
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
			vaultConfig: kms.VaultKMSPluginConfig{
				KMSPluginImage:     "quay.io/test/vault:v2",
				VaultAddress:       "https://vault.example.com:8200",
				VaultNamespace:     "my-namespace",
				VaultAuthNamespace: "my-auth-namespace",
				VaultKeyPath:       "transit/keys/my-key",
				Authentication: kms.VaultAuthentication{
					AppRole: kms.VaultAppRoleAuthentication{
						Secret: kms.VaultSecretReference{Name: "vault-approle"},
					},
				},
				TLS: kms.VaultTLSConfig{
					CABundle:   kms.VaultConfigMapReference{Name: "vault-ca-bundle"},
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
						"-vault-key-path=transit/keys/my-key",
						"-approle-role-id=test-role-id",
						"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-secret-vault-approle_secret-id-555",
						"-health-port=8081",
						"-metrics-port=9090",
						"-tls-ca-file=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555",
						"-tls-sni=vault.internal.example.com",
						"-vault-namespace=my-namespace",
						"-vault-auth-namespace=my-auth-namespace",
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
			vaultConfig: kms.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultNamespace: "my-namespace",
				VaultKeyPath:   "transit/keys/my-key",
				Authentication: kms.VaultAuthentication{
					AppRole: kms.VaultAppRoleAuthentication{
						Secret: kms.VaultSecretReference{Name: "vault-approle"},
					},
				},
				TLS: kms.VaultTLSConfig{
					CABundle: kms.VaultConfigMapReference{Name: "vault-ca-bundle"},
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
						"-vault-key-path=transit/keys/my-key",
						"-approle-role-id=test-role-id",
						"-approle-secret-id-path=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-secret-vault-approle_secret-id-555",
						"-health-port=8081",
						"-metrics-port=9090",
						"-tls-ca-file=/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555",
						"-vault-namespace=my-namespace",
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
			vaultConfig: kms.VaultKMSPluginConfig{
				KMSPluginImage: "quay.io/test/vault:v2",
				VaultAddress:   "https://vault.example.com:8200",
				VaultKeyPath:   "transit/keys/my-key",
				VaultNamespace: "",
				Authentication: kms.VaultAuthentication{
					AppRole: kms.VaultAppRoleAuthentication{
						Secret: kms.VaultSecretReference{Name: "vault-approle"},
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
						"-vault-key-path=transit/keys/my-key",
						"-approle-role-id=test-role-id-999",
						"-approle-secret-id-path=/var/run/secrets/kms-plugin/kms-plugin-secret-vault-approle_secret-id-999",
						"-health-port=8081",
						"-metrics-port=9090",
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
			vaultConfig: kms.VaultKMSPluginConfig{
				Authentication: kms.VaultAuthentication{
					AppRole: kms.VaultAppRoleAuthentication{
						Secret: kms.VaultSecretReference{Name: ""},
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

			ports := pluginPorts{health: defaultHealthPort, metrics: defaultMetricsPort}
			provider, err := newVaultSidecarProvider(tt.containerName, tt.keyID, tt.udsPath, tt.vaultConfig, refData, ports)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)

			container, err := provider.BuildSidecarContainer()
			require.NoError(t, err)

			for i := range tt.expectedContainers {
				if tt.expectedContainers[i].Name == provider.Name() {
					tt.expectedContainers[i] = withVaultLifecycle(tt.expectedContainers[i], ports)
				}
			}
			tt.inputContainers = append(tt.inputContainers, container)
			require.Equal(t, tt.expectedContainers, tt.inputContainers)
		})
	}
}

func expectedVaultPorts(ports pluginPorts) []corev1.ContainerPort {
	var out []corev1.ContainerPort
	if ports.healthEnabled() {
		health := corev1.ContainerPort{Name: "health", ContainerPort: ports.health, Protocol: corev1.ProtocolTCP}
		if ports.hostPort {
			health.HostPort = ports.health
		}
		out = append(out, health)
	}
	if ports.metricsEnabled() {
		metrics := corev1.ContainerPort{Name: "metrics", ContainerPort: ports.metrics, Protocol: corev1.ProtocolTCP}
		if ports.hostPort {
			metrics.HostPort = ports.metrics
		}
		out = append(out, metrics)
	}
	return out
}

func expectedStartupProbe(port int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(port)},
		},
		PeriodSeconds:    2,
		TimeoutSeconds:   1,
		FailureThreshold: 30,
	}
}

func expectedLivenessProbe(port int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(port)},
		},
		PeriodSeconds:    10,
		TimeoutSeconds:   5,
		FailureThreshold: 3,
	}
}

func expectedReadinessProbe(port int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(port)},
		},
		PeriodSeconds:    5,
		TimeoutSeconds:   5,
		FailureThreshold: 3,
	}
}

func withVaultLifecycle(c corev1.Container, ports pluginPorts) corev1.Container {
	if !ports.healthEnabled() && !ports.metricsEnabled() {
		return c
	}
	c.Ports = expectedVaultPorts(ports)
	if ports.healthEnabled() {
		c.StartupProbe = expectedStartupProbe(ports.health)
		c.LivenessProbe = expectedLivenessProbe(ports.health)
		c.ReadinessProbe = expectedReadinessProbe(ports.health)
	}
	return c
}
