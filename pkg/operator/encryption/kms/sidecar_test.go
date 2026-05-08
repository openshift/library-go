package kms

import (
	"encoding/json"
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/plugins"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
)

func TestNewSidecarProvider(t *testing.T) {
	tests := []struct {
		name           string
		config         *configv1.KMSConfig
		secretDataPath string
		wantErr        string
	}{
		{
			name:           "vault provider",
			secretDataPath: "/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-secret-data-1",
			config: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: configv1.VaultKMSConfig{
					KMSPluginImage: "quay.io/test/vault:v1",
					VaultAddress:   "https://vault.example.com:8200",
					TransitKey:     "my-key",
				},
			},
		},
		{
			name:           "unsupported provider",
			secretDataPath: "/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-secret-data-1",
			config:         &configv1.KMSConfig{},
			wantErr:        "unsupported KMS provider configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := newSidecarProvider(tt.config, tt.secretDataPath)
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
				Config: &configv1.VaultKMSConfig{
					KMSPluginImage: "quay.io/test/vault:v1",
					VaultAddress:   "https://vault.example.com:8200",
					VaultNamespace: "ns",
					TransitKey:     "key",
					TransitMount:   "transit",
				},
				SecretDataPath: "/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-secret-data-1",
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

func TestInjectIntoPodSpec(t *testing.T) {
	secretLister := func(secrets ...*corev1.Secret) corev1listers.SecretLister {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		for _, s := range secrets {
			indexer.Add(s)
		}
		return corev1listers.NewSecretLister(indexer)
	}

	vaultConfig := &configv1.KMSConfig{
		Type: configv1.VaultKMSProvider,
		Vault: configv1.VaultKMSConfig{
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
	providerConfigBytes, err := encoding.EncodeKMSConfig(vaultConfig)
	require.NoError(t, err)

	providerConfigKey, err := ToProviderConfigSecretDataKeyFor("555")
	require.NoError(t, err)

	credentialsKey, err := ToCredentialSecretDataKeyFor("555")
	require.NoError(t, err)

	credentials := map[string]string{
		"VAULT_ROLE_ID":   "role-id",
		"VAULT_SECRET_ID": "secret-id",
	}
	credentialsBytes, err := json.Marshal(credentials)
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
			providerConfigKey:   providerConfigBytes,
			credentialsKey:      credentialsBytes,
		},
	}

	credentialsFile := "/etc/kubernetes/static-pod-resources/secrets/encryption-config/kms-secret-data-555"
	sidecarArgs := fmt.Sprintf(`set -e
	CREDS=$(cat %s)
	SECRET_ID=${CREDS#*\"VAULT_SECRET_ID\":\"}
	SECRET_ID=${SECRET_ID%%%%\"*}
	ROLE_ID=${CREDS#*\"VAULT_ROLE_ID\":\"}
	ROLE_ID=${ROLE_ID%%%%\"*}
	printf '%%s' "$SECRET_ID" > /tmp/secret-id
	exec /vault-kube-kms \
	-listen-address=%s \
	-vault-address=%s \
	-vault-namespace=%s \
	-transit-mount=%s \
	-transit-key=%s \
	-approle-role-id=$ROLE_ID \
	-approle-secret-id-path=/tmp/secret-id`,
		credentialsFile,
		"unix:///var/run/kmsplugin/kms-555.sock",
		"https://vault.example.com:8200",
		"my-namespace",
		"transit",
		"my-key",
	)

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
	resourceDirMount := corev1.VolumeMount{
		Name:      "resource-dir",
		MountPath: "/etc/kubernetes/static-pod-resources",
		ReadOnly:  true,
	}
	resourceDirVolume := corev1.Volume{
		Name: "resource-dir",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/etc/kubernetes/static-pod-resources",
			},
		},
	}

	opConfig := OperatorConfig{
		EncryptionConfigNamespace:  "openshift-kube-apiserver",
		EncryptionConfigSecretName: "encryption-config",
		APIServerContainerName:     "kube-apiserver",
	}

	tests := []struct {
		name            string
		actualPodSpec   *corev1.PodSpec
		expectedPodSpec *corev1.PodSpec
		lister          corev1listers.SecretLister
		wantErr         string
	}{
		{
			name: "sidecar and volumes injected",
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
						Name:         "kms-plugin",
						Image:        "quay.io/test/vault:v1",
						Command:      []string{"/bin/sh", "-c"},
						Args:         []string{sidecarArgs},
						VolumeMounts: []corev1.VolumeMount{socketMount, resourceDirMount},
						SecurityContext: &corev1.SecurityContext{
							RunAsUser: ptr.To(int64(0)),
						},
					},
				},
				Volumes: []corev1.Volume{resourceDirVolume, socketVolume},
			},
			lister: secretLister(encryptionConfigSecret),
		},
		{
			name:          "nil pod spec",
			actualPodSpec: nil,
			lister:        secretLister(encryptionConfigSecret),
			wantErr:       "pod spec cannot be nil",
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
			lister: secretLister(),
		},
		{
			name: "missing encryption-config key in secret: pod spec unchanged",
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
			lister: secretLister(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "encryption-config",
					Namespace: "openshift-kube-apiserver",
				},
				Data: map[string][]byte{"other-key": []byte("data")},
			}),
		},
		{
			name: "no KMS provider in EncryptionConfiguration: pod spec unchanged",
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
			lister: func() corev1listers.SecretLister {
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
				return secretLister(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "encryption-config",
						Namespace: "openshift-kube-apiserver",
					},
					Data: map[string][]byte{"encryption-config": noKMSBytes},
				})
			}(),
		},
		{
			name: "missing API server container",
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
				},
			},
			lister:  secretLister(encryptionConfigSecret),
			wantErr: "container kube-apiserver not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InjectIntoPodSpec(tt.actualPodSpec, tt.lister, opConfig)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPodSpec, tt.actualPodSpec)
		})
	}
}
