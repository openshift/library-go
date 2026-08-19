package pluginlifecycle

import (
	"context"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	fake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/ptr"
)

func TestKMSPluginBuilder_Apply(t *testing.T) {
	f := newSidecarTestFixtures(t)

	secretClient := func(objs ...runtime.Object) corev1client.SecretsGetter {
		return fake.NewClientset(objs...).CoreV1()
	}

	tests := []struct {
		name string
		// containerName is the target container passed to Apply. Defaults to
		// "kube-apiserver" when empty.
		containerName string
		builder       *KMSPluginBuilder
		podSpec       *corev1.PodSpec
		verify        func(t *testing.T, podSpec *corev1.PodSpec)
		wantErr       string
	}{
		{
			name: "static pod mode: resource-dir mount and root UID",
			builder: NewKMSPluginBuilder().
				FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient(f.encryptionConfigSecret)).
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
				FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient(f.encryptionConfigSecret)),
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
			// Mirrors the preflight deployer, which calls Apply with the checker
			// container (deployer.go uses CheckContainerName) rather than the
			// apiserver. The preflight checker only fully verifies the first
			// socket, so the injected order must be keyID-descending (write key
			// first). The providers below are listed keyID-ascending on purpose to
			// prove Apply re-sorts them via ExtractUniqueAndSortedKMSConfigurations.
			name:          "preflight checker: sockets injected sorted by keyID descending",
			containerName: "kms-preflight-check",
			builder: NewKMSPluginBuilder().
				WithPreflightChecker().
				FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient(func() *corev1.Secret {
					multiEncConfig := &apiserverv1.EncryptionConfiguration{
						Resources: []apiserverv1.ResourceConfiguration{
							{
								Resources: []string{"secrets"},
								Providers: []apiserverv1.ProviderConfiguration{
									{KMS: &apiserverv1.KMSConfiguration{APIVersion: "v2", Name: "555_secrets", Endpoint: "unix:///var/run/kmsplugin/kms-555.sock"}},
									{KMS: &apiserverv1.KMSConfiguration{APIVersion: "v2", Name: "777_secrets", Endpoint: "unix:///var/run/kmsplugin/kms-777.sock"}},
								},
							},
						},
					}
					multiEncConfigBytes, err := encoding.EncodeEncryptionConfiguration(multiEncConfig)
					require.NoError(t, err)

					return &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: "encryption-config", Namespace: "openshift-kube-apiserver"},
						Data: map[string][]byte{
							"encryption-config": multiEncConfigBytes,
							// reuse the fixture's vault plugin config for both keys
							f.pluginConfigKey:                                        f.pluginConfigBytes,
							"kms-plugin-config-777":                                  f.pluginConfigBytes,
							"kms-plugin-secret-vault-approle_role-id-555":            []byte("test-role-id"),
							"kms-plugin-secret-vault-approle_secret-id-555":          []byte("test-secret-id"),
							"kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-555": []byte("test-ca-cert"),
							"kms-plugin-secret-vault-approle_role-id-777":            []byte("test-role-id"),
							"kms-plugin-secret-vault-approle_secret-id-777":          []byte("test-secret-id"),
							"kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-777": []byte("test-ca-cert"),
						},
					}
				}())),
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "kms-preflight-check"}},
				Volumes:    []corev1.Volume{f.resourceDirVolume},
			},
			verify: func(t *testing.T, podSpec *corev1.PodSpec) {
				var checker *corev1.Container
				for i := range podSpec.Containers {
					if podSpec.Containers[i].Name == "kms-preflight-check" {
						checker = &podSpec.Containers[i]
					}
				}
				require.NotNil(t, checker, "kms-preflight-check container must be present")
				require.Equal(t, []string{
					"--kms-sockets=unix:///var/run/kmsplugin/kms-777.sock,unix:///var/run/kmsplugin/kms-555.sock",
				}, checker.Args, "sockets must be injected exactly once, sorted by keyID descending (write key first)")
			},
		},
		{
			name: "missing secret: no-op",
			builder: NewKMSPluginBuilder().
				FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient()),
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "test"}},
			},
			verify: func(t *testing.T, podSpec *corev1.PodSpec) {
				require.Len(t, podSpec.InitContainers, 0, "no sidecars should be injected when secret is missing")
			},
		},
		{
			name: "nil pod spec: returns error",
			builder: NewKMSPluginBuilder().
				FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient(f.encryptionConfigSecret)),
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

			containerName := tt.containerName
			if containerName == "" {
				containerName = "kube-apiserver"
			}

			err := tt.builder.Apply(context.Background(), tt.podSpec, containerName)
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

	secretClient := func() corev1client.SecretsGetter {
		return fake.NewClientset(f.encryptionConfigSecret).CoreV1()
	}

	podSpec1 := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}
	podSpec2 := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}

	err := NewKMSPluginBuilder().
		FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient()).
		AsStaticPod().
		Apply(context.Background(), podSpec1, "kube-apiserver")
	require.NoError(t, err)

	err = NewKMSPluginBuilder().
		AsStaticPod().
		FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", secretClient()).
		Apply(context.Background(), podSpec2, "kube-apiserver")
	require.NoError(t, err)

	require.Equal(t, podSpec1, podSpec2, "order of builder calls must not affect the result")
}

func TestKMSPluginBuilder_Idempotent(t *testing.T) {
	f := newSidecarTestFixtures(t)
	sc := fake.NewClientset(f.encryptionConfigSecret).CoreV1()

	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "kube-apiserver"}},
		Volumes:    []corev1.Volume{f.resourceDirVolume},
	}

	apply := func() {
		t.Helper()
		err := NewKMSPluginBuilder().
			FromEncryptionConfigSecret("openshift-kube-apiserver", "encryption-config", sc).
			Apply(context.Background(), podSpec, "kube-apiserver")
		require.NoError(t, err)
	}

	apply()
	afterFirst := podSpec.DeepCopy()

	apply()
	require.Equal(t, afterFirst, podSpec, "second Apply must not change the pod spec")
}
