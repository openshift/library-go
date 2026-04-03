package kms

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	"github.com/stretchr/testify/require"
)

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

func TestFetchCredentials(t *testing.T) {
	tests := []struct {
		name        string
		kmsConfig   *configv1.KMSConfig
		secrets     []*corev1.Secret
		expectData  map[string][]byte
		expectError bool
	}{
		{
			name: "missing credential secret returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					ApproleSecretRef: configv1.SecretNameReference{Name: "vault-approle"},
				},
			},
			expectError: true,
		},
		{
			name: "credential secret with empty data returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					ApproleSecretRef: configv1.SecretNameReference{Name: "vault-approle"},
				},
			},
			secrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"}},
			},
			expectError: true,
		},
		{
			name: "credential secret returns data",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					ApproleSecretRef: configv1.SecretNameReference{Name: "vault-approle"},
				},
			},
			secrets: []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
					Data: map[string][]byte{
						"role_id":   []byte("my-role-id"),
						"secret_id": []byte("my-secret-id"),
					},
				},
			},
			expectData: map[string][]byte{
				"role_id":   []byte("my-role-id"),
				"secret_id": []byte("my-secret-id"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			for _, s := range tt.secrets {
				objs = append(objs, s)
			}
			kubeClient := fake.NewClientset(objs...)
			data, err := FetchCredentials(context.Background(), kubeClient.CoreV1(), tt.kmsConfig)

			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectData, data)
		})
	}
}

func TestFetchConfigMapData(t *testing.T) {
	tests := []struct {
		name        string
		kmsConfig   *configv1.KMSConfig
		configMaps  []*corev1.ConfigMap
		expectData  map[string]string
		expectError bool
	}{
		{
			name: "missing configmap returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					TLSCA: configv1.ConfigMapNameReference{Name: "vault-ca-bundle"},
				},
			},
			expectError: true,
		},
		{
			name: "configmap with empty data returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					TLSCA: configv1.ConfigMapNameReference{Name: "vault-ca-bundle"},
				},
			},
			configMaps: []*corev1.ConfigMap{
				{ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"}},
			},
			expectError: true,
		},
		{
			name: "configmap returns data",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					TLSCA: configv1.ConfigMapNameReference{Name: "vault-ca-bundle"},
				},
			},
			configMaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
					Data: map[string]string{
						"ca-bundle.crt": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					},
				},
			},
			expectData: map[string]string{
				"ca-bundle.crt": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			},
		},
		{
			name: "empty TLSCA name returns nil",
			kmsConfig: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			for _, cm := range tt.configMaps {
				objs = append(objs, cm)
			}
			kubeClient := fake.NewClientset(objs...)
			data, err := FetchConfigMapData(context.Background(), kubeClient.CoreV1(), tt.kmsConfig)

			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectData, data)
		})
	}
}
