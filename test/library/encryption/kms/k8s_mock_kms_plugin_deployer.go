package kms

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

//go:embed assets
var assetsFS embed.FS

const (
	// WellKnownUpstreamMockKMSPluginNamespace is the default namespace where the KMS plugin runs.
	WellKnownUpstreamMockKMSPluginNamespace = "k8s-mock-plugin"

	// WellKnownUpstreamMockKMSPluginImage is the pre-built mock KMS plugin image.
	WellKnownUpstreamMockKMSPluginImage = "quay.io/openshifttest/mock-kms-plugin@sha256:998e1d48eba257f589ab86c30abd5043f662213e9aeff253e1c308301879d48a"

	// defaultPollTimeout the default poll timeout used by the deployer
	defaultPollTimeout = 2 * time.Minute
)

var manifestFilesToApplyDirectly = []string{
	"k8s_mock_kms_plugin_namespace.yaml",
	"k8s_mock_kms_plugin_serviceaccount.yaml",
	"k8s_mock_kms_plugin_rolebinding.yaml",
	"k8s_mock_kms_plugin_configmap.yaml",
}

var daemonSetManifestFile = "k8s_mock_kms_plugin_daemonset.yaml"

// yamlTemplateData holds the template variables for YAML manifests.
// Fields must be exported (uppercase) for Go templates to access them.
type yamlTemplateData struct {
	Namespace string
	Image     string
}

// DeployUpstreamMockKMSPlugin deploys the upstream mock KMS v2 plugin using embedded YAML assets.
// It returns a cleanup function that removes the entire namespace where the DaemonSet was deployed.
func DeployUpstreamMockKMSPlugin(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace, image string) func() {
	t.Helper()

	if err := destroyNamespaceIfNotExists(ctx, t, kubeClient, namespace); err != nil {
		t.Fatalf("Failed to cleanup existing namespace %q: %v", namespace, err)
	}

	t.Logf("Deploying upstream mock KMS v2 plugin in namespace %q using image %s", namespace, image)
	daemonSetName, err := applyUpstreamMockKMSPluginManifests(ctx, t, kubeClient, namespace, image)
	if err != nil {
		t.Fatalf("Failed to apply manifests: %v", err)
	}
	if err := waitForDaemonSetReady(ctx, t, kubeClient, namespace, daemonSetName); err != nil {
		t.Fatalf("DaemonSet not ready: %v", err)
	}
	t.Logf("Upstream mock KMS v2 plugin deployed successfully!")

	return func() {
		// Before destroying the namespace, collect the logs of the pods in namespace
		collectPodLogs(ctx, t, kubeClient, namespace)

		if err := destroyNamespaceIfNotExists(ctx, t, kubeClient, namespace); err != nil {
			t.Errorf("Failed to cleanup namespace %q: %v", namespace, err)
		}
	}
}

// collectPodLogs collects logs from all pods in the namespace and writes them to ARTIFACT_DIR.
func collectPodLogs(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace string) {
	t.Helper()

	artifactDir := os.Getenv("ARTIFACT_DIR")
	if artifactDir == "" {
		t.Log("artifact directory not set. Skipping collection of pod logs...")
		return
	}

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Logf("Failed to list pods: %v", err)
		return
	}
	if len(pods.Items) == 0 {
		t.Logf("No pods found in %s", namespace)
		return
	}

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			func() {
				logFileName := filepath.Join(artifactDir, fmt.Sprintf("%s_%s_%s_%s.log", namespace, t.Name(), pod.Name, container.Name))

				logOpts := &corev1.PodLogOptions{Container: container.Name}
				logs, err := kubeClient.CoreV1().Pods(namespace).GetLogs(pod.Name, logOpts).Stream(ctx)
				if err != nil {
					t.Logf("Pod %s logs can not be captured err: %v", pod.Name, err)
					return
				}
				defer logs.Close()

				logFile, err := os.Create(logFileName)
				if err != nil {
					t.Logf("creating log file %s failed: %v", logFileName, err)
					return
				}
				defer logFile.Close()

				_, err = io.Copy(logFile, logs)
				if err != nil {
					t.Logf("failed to copying logs: %v", err)
				}
			}()
		}
	}
}

// applyUpstreamMockKMSPluginManifests applies all the KMS plugin manifests.
// Returns the DaemonSet name on success.
func applyUpstreamMockKMSPluginManifests(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace, image string) (string, error) {
	t.Helper()

	data := yamlTemplateData{
		Namespace: namespace,
		Image:     image,
	}

	recorder := events.NewInMemoryRecorder("k8s-mock-kms-plugin-deployer", clock.RealClock{})
	assetFunc := wrapAssetWithTemplateDataFunc(data)

	clientHolder := resourceapply.NewKubeClientHolder(kubeClient)
	results := resourceapply.ApplyDirectly(ctx, clientHolder, recorder, resourceapply.NewResourceCache(), assetFunc, manifestFilesToApplyDirectly...)

	for _, result := range results {
		if result.Error != nil {
			return "", result.Error
		}
		t.Logf("Applied %s (changed=%v)", result.File, result.Changed)
	}

	rawDaemonSet, err := assetFunc(daemonSetManifestFile)
	if err != nil {
		return "", err
	}

	daemonSet := resourceread.ReadDaemonSetV1OrDie(rawDaemonSet)
	_, _, err = resourceapply.ApplyDaemonSet(ctx, kubeClient.AppsV1(), recorder, daemonSet, -1)
	if err != nil {
		return "", err
	}
	t.Logf("Applied DaemonSet %s/%s", namespace, daemonSet.Name)

	return daemonSet.Name, nil
}

// waitForDaemonSetReady waits for the KMS plugin DaemonSet to be ready.
func waitForDaemonSetReady(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace, daemonSetName string) error {
	t.Helper()

	t.Logf("Waiting for DaemonSet %s/%s to be ready...", namespace, daemonSetName)

	return wait.PollUntilContextTimeout(ctx, time.Second, defaultPollTimeout, true, func(ctx context.Context) (bool, error) {
		ds, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, daemonSetName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}

		t.Logf("DaemonSet %s/%s status: desired=%d, ready=%d, available=%d",
			namespace, daemonSetName, ds.Status.DesiredNumberScheduled, ds.Status.NumberReady, ds.Status.NumberAvailable)

		// for simplicity just ensure at least one pod is scheduled before checking readiness
		if ds.Status.DesiredNumberScheduled == 0 {
			return false, nil
		}
		return ds.Status.NumberReady == ds.Status.DesiredNumberScheduled, nil
	})
}

// destroyNamespaceIfNotExists removes the namespace and waits for deletion.
func destroyNamespaceIfNotExists(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace string) error {
	t.Helper()

	t.Logf("Deleting namespace %q", namespace)
	err := kubeClient.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return wait.PollUntilContextTimeout(ctx, time.Second, defaultPollTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := kubeClient.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			t.Logf("Namespace %q deleted", namespace)
			return true, nil
		}
		return false, nil
	})
}

// wrapAssetWithTemplateDataFunc returns an AssetFunc that templates the YAML with the given data.
func wrapAssetWithTemplateDataFunc(data yamlTemplateData) resourceapply.AssetFunc {
	return func(name string) ([]byte, error) {
		content, err := assetsFS.ReadFile(filepath.Join("assets", name))
		if err != nil {
			return nil, err
		}

		tmpl, err := template.New(name).Parse(string(content))
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}
}
