package pluginlifecycle

import (
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func TestKMSPluginBuilder_Apply(t *testing.T) {
	f := newSidecarTestFixtures(t)
	cfg, err := encryptiondata.FromSecret(f.encryptionConfigSecret)
	require.NoError(t, err)

	tests := []struct {
		name    string
		builder *KMSPluginBuilder
		podSpec *corev1.PodSpec
		verify  func(t *testing.T, podSpec *corev1.PodSpec)
		wantErr string
	}{
		{
			name: "static pod mode: resource-dir mount and root UID",
			builder: NewKMSPluginBuilder().
				FromEncryptionConfig("encryption-config", cfg).
				AsStaticPod(),
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "kube-apiserver"}},
				Volumes:    []corev1.Volume{f.resourceDirVolume},
			},
			verify: func(t *testing.T, podSpec *corev1.PodSpec) {
				require.Len(t, podSpec.InitContainers, 1)
				sidecar := podSpec.InitContainers[0]
				require.Equal(t, "vault-kms-plugin-555", sidecar.Name)
				require.Equal(t, ptr.To(int64(0)), sidecar.SecurityContext.RunAsUser)

				hasResourceDirMount := false
				for _, m := range sidecar.VolumeMounts {
					if m.Name == "resource-dir" {
						hasResourceDirMount = true
						require.Equal(t, "/etc/kubernetes/static-pod-resources", m.MountPath)
						require.True(t, m.ReadOnly)
					}
				}
				require.True(t, hasResourceDirMount, "sidecar must have resource-dir volume mount")

				for _, v := range podSpec.Volumes {
					require.NotEqual(t, "kms-plugins-data", v.Name, "static pod mode should not add kms-plugins-data volume")
				}
			},
		},
		{
			name: "deployment mode: secret volume mount and no root UID",
			builder: NewKMSPluginBuilder().
				FromEncryptionConfig("encryption-config", cfg),
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "kube-apiserver"}},
				Volumes:    []corev1.Volume{f.resourceDirVolume},
			},
			verify: func(t *testing.T, podSpec *corev1.PodSpec) {
				require.Len(t, podSpec.InitContainers, 1)
				sidecar := podSpec.InitContainers[0]
				require.Equal(t, "vault-kms-plugin-555", sidecar.Name)
				require.Nil(t, sidecar.SecurityContext.RunAsUser)

				hasRefDataMount := false
				for _, m := range sidecar.VolumeMounts {
					if m.Name == "kms-plugins-data" {
						hasRefDataMount = true
						require.Equal(t, "/var/run/secrets/kms-plugin", m.MountPath)
						require.True(t, m.ReadOnly)
					}
				}
				require.True(t, hasRefDataMount, "sidecar must have kms-plugins-data volume mount")

				hasRefDataVolume := false
				for _, v := range podSpec.Volumes {
					if v.Name == "kms-plugins-data" {
						hasRefDataVolume = true
						require.Equal(t, "encryption-config", v.Secret.SecretName)
					}
				}
				require.True(t, hasRefDataVolume, "deployment mode must add kms-plugins-data volume")
			},
		},
		{
			name:    "no encryption config: returns error",
			builder: NewKMSPluginBuilder(),
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "test"}},
			},
			wantErr: "encryption configuration is required",
		},
		{
			name: "nil pod spec: returns error",
			builder: NewKMSPluginBuilder().
				FromEncryptionConfig("encryption-config", cfg),
			podSpec: nil,
			wantErr: "pod spec cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var original *corev1.PodSpec
			if tt.podSpec != nil {
				original = tt.podSpec.DeepCopy()
			}

			err := tt.builder.Apply(tt.podSpec, "kube-apiserver")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				if original != nil {
					require.Equal(t, original, tt.podSpec, "pod spec should be unchanged on error")
				}
				return
			}
			require.NoError(t, err)
			tt.verify(t, tt.podSpec)
		})
	}
}

func TestKMSPluginBuilder_OrderIndependence(t *testing.T) {
	f := newSidecarTestFixtures(t)
	cfg, err := encryptiondata.FromSecret(f.encryptionConfigSecret)
	require.NoError(t, err)

	podSpec1 := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}
	podSpec2 := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}

	err = NewKMSPluginBuilder().
		FromEncryptionConfig("encryption-config", cfg).
		AsStaticPod().
		Apply(podSpec1, "kube-apiserver")
	require.NoError(t, err)

	err = NewKMSPluginBuilder().
		AsStaticPod().
		FromEncryptionConfig("encryption-config", cfg).
		Apply(podSpec2, "kube-apiserver")
	require.NoError(t, err)

	require.Equal(t, podSpec1, podSpec2, "order of builder calls must not affect the result")
}

func TestKMSPluginBuilder_Idempotent(t *testing.T) {
	f := newSidecarTestFixtures(t)
	cfg, err := encryptiondata.FromSecret(f.encryptionConfigSecret)
	require.NoError(t, err)

	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}

	apply := func() {
		t.Helper()
		err := NewKMSPluginBuilder().
			FromEncryptionConfig("encryption-config", cfg).
			Apply(podSpec, "kube-apiserver")
		require.NoError(t, err)
	}

	apply()
	afterFirst := podSpec.DeepCopy()

	apply()
	require.Equal(t, afterFirst, podSpec, "second Apply must not change the pod spec")
}
