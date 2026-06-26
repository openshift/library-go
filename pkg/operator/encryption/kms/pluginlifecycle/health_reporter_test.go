package pluginlifecycle

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	fake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func TestKMSPluginBuilder_WithHealthReporter(t *testing.T) {
	f := newSidecarTestFixtures(t)
	sc := fake.NewClientset(f.encryptionConfigSecret).CoreV1()

	t.Run("health reporter injected with correct args and socket mount", func(t *testing.T) {
		podSpec := &corev1.PodSpec{
			Containers: []corev1.Container{{Name: "kube-apiserver"}},
			Volumes:    []corev1.Volume{f.resourceDirVolume},
		}
		err := NewKMSPluginBuilder(sc).
			FromEncryptionConfig("openshift-kube-apiserver", "encryption-config").
			WithHealthReporter("cluster-kube-apiserver-operator", "quay.io/test/operator:latest").
			Apply(context.Background(), podSpec, "kube-apiserver")
		require.NoError(t, err)

		var reporter *corev1.Container
		for i := range podSpec.InitContainers {
			if podSpec.InitContainers[i].Name == "kms-health-reporter" {
				reporter = &podSpec.InitContainers[i]
				break
			}
		}
		require.NotNil(t, reporter, "health reporter container must be injected")
		require.Equal(t, "quay.io/test/operator:latest", reporter.Image)
		require.Equal(t, []string{"cluster-kube-apiserver-operator", "kms-health-reporter"}, reporter.Command)
		require.Contains(t, reporter.Args, "--kms-sockets=unix:///var/run/kmsplugin/kms-555.sock")
		require.Contains(t, reporter.Args, "--node-name=$(NODE_NAME)")

		hasSocketMount := false
		for _, m := range reporter.VolumeMounts {
			if m.Name == "kms-plugin-socket" {
				hasSocketMount = true
				require.True(t, m.ReadOnly)
			}
		}
		require.True(t, hasSocketMount)

		require.Len(t, reporter.Env, 1)
		require.Equal(t, "NODE_NAME", reporter.Env[0].Name)
		require.Equal(t, "spec.nodeName", reporter.Env[0].ValueFrom.FieldRef.FieldPath)
	})

	t.Run("static pod mode: health reporter gets root UID", func(t *testing.T) {
		podSpec := &corev1.PodSpec{
			Containers: []corev1.Container{{Name: "kube-apiserver"}},
			Volumes:    []corev1.Volume{f.resourceDirVolume},
		}
		err := NewKMSPluginBuilder(sc).
			FromEncryptionConfig("openshift-kube-apiserver", "encryption-config").
			AsStaticPod().
			WithHealthReporter("cluster-kube-apiserver-operator", "quay.io/test/operator:latest").
			Apply(context.Background(), podSpec, "kube-apiserver")
		require.NoError(t, err)

		var reporter *corev1.Container
		for i := range podSpec.InitContainers {
			if podSpec.InitContainers[i].Name == "kms-health-reporter" {
				reporter = &podSpec.InitContainers[i]
				break
			}
		}
		require.NotNil(t, reporter)
		require.Equal(t, ptr.To(int64(0)), reporter.SecurityContext.RunAsUser)
		require.Contains(t, reporter.Args, "--kubeconfig=/etc/kubernetes/static-pod-resources/configmaps/kube-apiserver-cert-syncer-kubeconfig/kubeconfig")
	})

	t.Run("without WithHealthReporter: no health reporter", func(t *testing.T) {
		podSpec := &corev1.PodSpec{
			Containers: []corev1.Container{{Name: "kube-apiserver"}},
			Volumes:    []corev1.Volume{f.resourceDirVolume},
		}
		err := NewKMSPluginBuilder(sc).
			FromEncryptionConfig("openshift-kube-apiserver", "encryption-config").
			Apply(context.Background(), podSpec, "kube-apiserver")
		require.NoError(t, err)

		for _, c := range podSpec.InitContainers {
			require.NotEqual(t, "kms-health-reporter", c.Name, "health reporter must not be injected without WithHealthReporter")
		}
	})

	t.Run("empty image: returns error", func(t *testing.T) {
		podSpec := &corev1.PodSpec{
			Containers: []corev1.Container{{Name: "kube-apiserver"}},
			Volumes:    []corev1.Volume{f.resourceDirVolume},
		}
		err := NewKMSPluginBuilder(sc).
			FromEncryptionConfig("openshift-kube-apiserver", "encryption-config").
			WithHealthReporter("cluster-kube-apiserver-operator", "").
			Apply(context.Background(), podSpec, "kube-apiserver")
		require.ErrorContains(t, err, "health reporter name, operatorBinary, image and subcommand are required")
	})
}
