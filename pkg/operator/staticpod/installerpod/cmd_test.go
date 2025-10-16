package installerpod

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

const podYaml = `
apiVersion: v1
kind: Pod
metadata:
  namespace: some-ns
  name: kube-apiserver-pod
spec:
`

const secondPodYaml = `
apiVersion: v1
kind: Pod
metadata:
  namespace: some-ns
  name: kube-apiserver-startup-monitor
spec:
`

func TestCopyContent(t *testing.T) {
	tests := []struct {
		name string

		o      InstallOptions
		client func() *fake.Clientset

		expectedErr string
		expected    func(t *testing.T, resourceDir, podDir string)
	}{
		{
			name: "basic",
			o: InstallOptions{
				Revision:               "006",
				Namespace:              "some-ns",
				PodConfigMapNamePrefix: "kube-apiserver-pod",
				SecretNamePrefixes:     []string{"first", "second", "third"},
				ConfigMapNamePrefixes:  []string{"alpha", "bravo", "delta"},
			},
			client: func() *fake.Clientset {
				return fake.NewSimpleClientset(
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "first-006"},
						Data: map[string][]byte{
							"one-A.crt": []byte("one"),
							"two-A.crt": []byte("two"),
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "second-006"},
						Data: map[string][]byte{
							"uno-B.crt": []byte("uno"),
							"dos-B.crt": []byte("dos"),
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "third-006"},
						Data: map[string][]byte{
							"run-third.sh": []byte("echo third"),
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "alpha-006"},
						Data: map[string]string{
							"apple-A.crt":  "apple",
							"banana-A.crt": "banana",
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "bravo-006"},
						Data: map[string]string{
							"manzana-B.crt": "manzana",
							"platano-B.crt": "platano",
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "kube-apiserver-pod-006"},
						Data: map[string]string{
							"pod.yaml": podYaml,
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "delta-006"},
						Data: map[string]string{
							"run-delta.sh": "echo delta",
						},
					},
				)
			},
			expected: func(t *testing.T, resourceDir, podDir string) {
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "first", "one-A.crt"), "one", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "first", "two-A.crt"), "two", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "second", "uno-B.crt"), "uno", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "second", "dos-B.crt"), "dos", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "third", "run-third.sh"), "echo third", 0700)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "alpha", "apple-A.crt"), "apple", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "alpha", "banana-A.crt"), "banana", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "bravo", "manzana-B.crt"), "manzana", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "bravo", "platano-B.crt"), "platano", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "delta", "run-delta.sh"), "echo delta", 0755)
				checkFileContentMatchesPod(t, path.Join(resourceDir, "kube-apiserver-pod-006", "kube-apiserver-pod.yaml"), podYaml)
				checkFileContentMatchesPod(t, path.Join(podDir, "kube-apiserver-pod.yaml"), podYaml)
			},
		},
		{
			name: "optional-secrets-configmaps",
			o: InstallOptions{
				Revision:                      "006",
				Namespace:                     "some-ns",
				PodConfigMapNamePrefix:        "kube-apiserver-pod",
				SecretNamePrefixes:            []string{"first", "second"},
				OptionalSecretNamePrefixes:    []string{"third", "fourth"},
				ConfigMapNamePrefixes:         []string{"alpha", "bravo"},
				OptionalConfigMapNamePrefixes: []string{"charlie", "delta"},
			},
			client: func() *fake.Clientset {
				return fake.NewSimpleClientset(
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "first-006"},
						Data: map[string][]byte{
							"one-A.crt": []byte("one"),
							"two-A.crt": []byte("two"),
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "second-006"},
						Data: map[string][]byte{
							"uno-B.crt": []byte("uno"),
							"dos-B.crt": []byte("dos"),
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "third-006"},
						Data: map[string][]byte{
							"tres-C.crt":   []byte("tres"),
							"cuatro-C.crt": []byte("cuatro"),
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "alpha-006"},
						Data: map[string]string{
							"apple-A.crt":  "apple",
							"banana-A.crt": "banana",
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "bravo-006"},
						Data: map[string]string{
							"manzana-B.crt": "manzana",
							"platano-B.crt": "platano",
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "charlie-006"},
						Data: map[string]string{
							"apple-C.crt":  "apple",
							"banana-C.crt": "banana",
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "kube-apiserver-pod-006"},
						Data: map[string]string{
							"pod.yaml": podYaml,
						},
					},
				)
			},
			expected: func(t *testing.T, resourceDir, podDir string) {
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "first", "one-A.crt"), "one", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "first", "two-A.crt"), "two", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "second", "uno-B.crt"), "uno", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "second", "dos-B.crt"), "dos", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "third", "tres-C.crt"), "tres", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "secrets", "third", "cuatro-C.crt"), "cuatro", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "alpha", "apple-A.crt"), "apple", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "alpha", "banana-A.crt"), "banana", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "bravo", "manzana-B.crt"), "manzana", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "bravo", "platano-B.crt"), "platano", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "charlie", "apple-C.crt"), "apple", 0600)
				checkFileContent(t, path.Join(resourceDir, "kube-apiserver-pod-006", "configmaps", "charlie", "banana-C.crt"), "banana", 0600)
				checkFileContentMatchesPod(t, path.Join(resourceDir, "kube-apiserver-pod-006", "kube-apiserver-pod.yaml"), podYaml)
				checkFileContentMatchesPod(t, path.Join(podDir, "kube-apiserver-pod.yaml"), podYaml)
			},
		},

		{
			name: "optional pod in pod cm",
			o: InstallOptions{
				Revision:               "006",
				Namespace:              "some-ns",
				PodConfigMapNamePrefix: "kube-apiserver-pod",
			},
			client: func() *fake.Clientset {
				return fake.NewSimpleClientset(
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "some-ns", Name: "kube-apiserver-pod-006"},
						Data: map[string]string{
							"pod.yaml": podYaml,
							"kube-apiserver-startup-monitor-pod.yaml": secondPodYaml,
						},
					},
				)
			},
			expected: func(t *testing.T, resourceDir, podDir string) {
				checkFileContentMatchesPod(t, path.Join(resourceDir, "kube-apiserver-pod-006", "kube-apiserver-pod.yaml"), podYaml)
				checkFileContentMatchesPod(t, path.Join(resourceDir, "kube-apiserver-pod-006", "kube-apiserver-startup-monitor-pod.yaml"), secondPodYaml)
				checkFileContentMatchesPod(t, path.Join(podDir, "kube-apiserver-pod.yaml"), podYaml)
				checkFileContentMatchesPod(t, path.Join(podDir, "kube-apiserver-startup-monitor-pod.yaml"), secondPodYaml)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testDir := t.TempDir()

			o := test.o
			o.KubeClient = test.client()
			o.ResourceDir = path.Join(testDir, "resources")
			o.PodManifestDir = path.Join(testDir, "static-pods")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err := o.copyContent(ctx)
			switch {
			case err == nil && len(test.expectedErr) == 0:
			case err != nil && len(test.expectedErr) == 0:
				t.Fatal(err)
			case err == nil && len(test.expectedErr) != 0:
				t.Fatalf("missing %q", test.expectedErr)
			case err != nil && !strings.Contains(err.Error(), test.expectedErr):
				t.Fatalf("expected %q, got %q", test.expectedErr, err.Error())
			}
			test.expected(t, o.ResourceDir, o.PodManifestDir)
		})
	}
}

func TestKubeletVersion(t *testing.T) {
	o := &InstallOptions{}
	o.KubeletVersion = "1.23.1+1b2affc"
	if o.installerPodNeedUUID() {
		t.Fatalf("kubelet \"v1.22.1+1b2affc\" does not need UID")
	}

	o.KubeletVersion = "1.20.0+b12afff"
	if !o.installerPodNeedUUID() {
		t.Fatalf("kubelet \"v1.20.0+1b2affc\" need UID")
	}
}

func checkFileContent(t *testing.T, file, expected string, expectedPerm os.FileMode) {
	actualBytes, err := os.ReadFile(file)
	if err != nil {
		t.Error(err)
		return
	}
	actual := string(actualBytes)

	stat, err := os.Stat(file)
	if err != nil {
		t.Errorf("Failed to stat %q: %v", file, err)
		return
	}
	if gotPerm := stat.Mode().Perm(); gotPerm != expectedPerm {
		t.Errorf("File permissions mismatch for %q: expected %v, got %v", file, gotPerm, expectedPerm)
	}

	if !cmp.Equal(expected, actual) {
		t.Errorf("File content mismatch for %q:\n%s", file, cmp.Diff(expected, actual))
	}
}

func checkFileContentMatchesPod(t *testing.T, file, expected string) {
	actual, err := os.ReadFile(file)
	if err != nil {
		t.Error(err)
		return
	}

	actualPod, err := resourceread.ReadPodV1(actual)
	if err != nil {
		t.Error(err)
	}
	expectedPod, err := resourceread.ReadPodV1([]byte(expected))
	if err != nil {
		t.Error(err)
	}

	// UID is auto generated so just rewrite it
	expectedPod.UID = actualPod.UID

	if !equality.Semantic.DeepEqual(actualPod, expectedPod) {
		t.Errorf("unexpected pod was written %v", actualPod)
	}
}
