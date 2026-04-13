package kms

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	WellKnownVaultKMSPluginNamespace = "openshift-kms-plugin"
	WellKnownVaultKMSPluginImage     = "quay.io/openshifttest/vault-kms-plugin:latest"

	vaultStaticPodManifest    = "vault_kms_plugin_static_pod.yaml"
	vaultStaticPodName        = "vault-kms-plugin"
	vaultManifestPathOnHost   = "/etc/kubernetes/manifests/vault-kms-plugin.yaml"
	vaultSocketDir            = "/var/run/kmsplugin"
	vaultStaticPodPollTimeout = 3 * time.Minute
)

// VaultKMSPluginDeployer deploys a Vault KMS plugin as a static pod on each
// control-plane node by writing the manifest to /etc/kubernetes/manifests/.
// This mirrors production deployment where vault-kube-kms runs as a static pod
// managed by the kubelet.
type VaultKMSPluginDeployer struct {
	namespace string
	image     string
}

func NewVaultKMSPluginDeployer(namespace, image string) *VaultKMSPluginDeployer {
	return &VaultKMSPluginDeployer{
		namespace: namespace,
		image:     image,
	}
}

func (d *VaultKMSPluginDeployer) Name() string {
	return "vault"
}

func (d *VaultKMSPluginDeployer) Deploy(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface) {
	t.Helper()

	t.Logf("Deploying Vault KMS plugin as static pod using image %s", d.image)

	manifest, err := d.renderManifest()
	if err != nil {
		t.Fatalf("Failed to render Vault static pod manifest: %v", err)
	}

	nodes, err := d.getControlPlaneNodes(ctx, kubeClient)
	if err != nil {
		t.Fatalf("Failed to list control-plane nodes: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatalf("No control-plane nodes found")
	}

	if err := d.ensureNamespace(ctx, kubeClient); err != nil {
		t.Fatalf("Failed to ensure namespace %s: %v", d.namespace, err)
	}

	if err := d.ensureSocketDir(ctx, t, kubeClient, nodes); err != nil {
		t.Fatalf("Failed to ensure socket directory on nodes: %v", err)
	}

	if err := d.writeManifestToNodes(ctx, t, kubeClient, nodes, manifest); err != nil {
		t.Fatalf("Failed to write static pod manifest to nodes: %v", err)
	}

	if err := d.waitForStaticPods(ctx, t, kubeClient, nodes); err != nil {
		t.Fatalf("Vault mock KMS static pods not ready: %v", err)
	}

	t.Logf("Vault KMS plugin deployed successfully on %d control-plane node(s)", len(nodes))
}

func (d *VaultKMSPluginDeployer) Cleanup(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface) {
	t.Helper()

	t.Logf("Cleaning up Vault KMS plugin")

	nodes, err := d.getControlPlaneNodes(ctx, kubeClient)
	if err != nil {
		t.Logf("Warning: failed to list control-plane nodes for cleanup: %v", err)
		return
	}

	for _, node := range nodes {
		if err := d.removeManifestFromNode(ctx, t, kubeClient, node); err != nil {
			t.Logf("Warning: failed to remove manifest from node %s: %v", node.Name, err)
		}
	}

	if err := d.waitForStaticPodsGone(ctx, t, kubeClient, nodes); err != nil {
		t.Logf("Warning: static pods did not terminate: %v", err)
	}
}

func (d *VaultKMSPluginDeployer) renderManifest() (string, error) {
	content, err := assetsFS.ReadFile(filepath.Join("assets", vaultStaticPodManifest))
	if err != nil {
		return "", fmt.Errorf("reading vault manifest template: %w", err)
	}

	tmpl, err := template.New(vaultStaticPodManifest).Parse(string(content))
	if err != nil {
		return "", fmt.Errorf("parsing vault manifest template: %w", err)
	}

	data := yamlTemplateData{
		Namespace: d.namespace,
		Image:     d.image,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing vault manifest template: %w", err)
	}

	return buf.String(), nil
}

func (d *VaultKMSPluginDeployer) getControlPlaneNodes(ctx context.Context, kubeClient kubernetes.Interface) ([]corev1.Node, error) {
	nodeList, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		LabelSelector: "node-role.kubernetes.io/control-plane",
	})
	if err != nil {
		return nil, err
	}
	return nodeList.Items, nil
}

func (d *VaultKMSPluginDeployer) ensureNamespace(ctx context.Context, kubeClient kubernetes.Interface) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: d.namespace,
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "privileged",
				"pod-security.kubernetes.io/audit":   "privileged",
				"pod-security.kubernetes.io/warn":    "privileged",
			},
		},
	}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// ensureSocketDir creates the KMS socket directory on each node via a
// privileged debug pod.
func (d *VaultKMSPluginDeployer) ensureSocketDir(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, nodes []corev1.Node) error {
	for _, node := range nodes {
		t.Logf("Ensuring socket directory %s on node %s", vaultSocketDir, node.Name)
		if err := d.execOnNode(ctx, t, kubeClient, node,
			fmt.Sprintf("mkdir -p %s", vaultSocketDir)); err != nil {
			return fmt.Errorf("node %s: %w", node.Name, err)
		}
	}
	return nil
}

// writeManifestToNodes writes the static pod manifest to each control-plane
// node's manifest directory.
func (d *VaultKMSPluginDeployer) writeManifestToNodes(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, nodes []corev1.Node, manifest string) error {
	for _, node := range nodes {
		t.Logf("Writing static pod manifest to node %s at %s", node.Name, vaultManifestPathOnHost)
		cmd := fmt.Sprintf("cat > %s << 'EOFMANIFEST'\n%sEOFMANIFEST", vaultManifestPathOnHost, manifest)
		if err := d.execOnNode(ctx, t, kubeClient, node, cmd); err != nil {
			return fmt.Errorf("node %s: %w", node.Name, err)
		}
	}
	return nil
}

func (d *VaultKMSPluginDeployer) removeManifestFromNode(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, node corev1.Node) error {
	t.Logf("Removing static pod manifest from node %s", node.Name)
	return d.execOnNode(ctx, t, kubeClient, node,
		fmt.Sprintf("rm -f %s", vaultManifestPathOnHost))
}

// execOnNode runs a command on a node by creating a privileged pod that
// mounts the host filesystem via chroot.
func (d *VaultKMSPluginDeployer) execOnNode(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, node corev1.Node, command string) error {
	podName := fmt.Sprintf("kms-node-exec-%s", node.Name)
	privileged := true
	hostPathType := corev1.HostPathDirectory

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: d.namespace,
		},
		Spec: corev1.PodSpec{
			NodeName:      node.Name,
			RestartPolicy: corev1.RestartPolicyNever,
			HostPID:       true,
			Containers: []corev1.Container{
				{
					Name:  "exec",
					Image: "registry.access.redhat.com/ubi9/ubi-minimal:latest",
					Command: []string{
						"/bin/sh", "-c",
						fmt.Sprintf("chroot /host /bin/sh -c '%s'", command),
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &privileged,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "host", MountPath: "/host"},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
							Type: &hostPathType,
						},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
			},
		},
	}

	_, err := kubeClient.CoreV1().Pods(d.namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating exec pod: %w", err)
	}
	defer func() {
		_ = kubeClient.CoreV1().Pods(d.namespace).Delete(ctx, podName, metav1.DeleteOptions{})
	}()

	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, defaultPollTimeout, true, func(ctx context.Context) (bool, error) {
		p, err := kubeClient.CoreV1().Pods(d.namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		switch p.Status.Phase {
		case corev1.PodSucceeded:
			return true, nil
		case corev1.PodFailed:
			return false, fmt.Errorf("exec pod %s failed", podName)
		}
		return false, nil
	})

	return err
}

func (d *VaultKMSPluginDeployer) waitForStaticPods(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, nodes []corev1.Node) error {
	t.Logf("Waiting for Vault mock KMS static pods to be ready on %d node(s)...", len(nodes))

	return wait.PollUntilContextTimeout(ctx, 5*time.Second, vaultStaticPodPollTimeout, true, func(ctx context.Context) (bool, error) {
		for _, node := range nodes {
			mirrorPodName := fmt.Sprintf("%s-%s", vaultStaticPodName, node.Name)
			pod, err := kubeClient.CoreV1().Pods(d.namespace).Get(ctx, mirrorPodName, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					t.Logf("Mirror pod %s/%s not found yet", d.namespace, mirrorPodName)
					return false, nil
				}
				return false, err
			}
			if pod.Status.Phase != corev1.PodRunning {
				t.Logf("Mirror pod %s/%s phase=%s", d.namespace, mirrorPodName, pod.Status.Phase)
				return false, nil
			}
			ready := false
			for _, c := range pod.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready {
				t.Logf("Mirror pod %s/%s not ready yet", d.namespace, mirrorPodName)
				return false, nil
			}
		}
		return true, nil
	})
}

func (d *VaultKMSPluginDeployer) waitForStaticPodsGone(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, nodes []corev1.Node) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, defaultPollTimeout, true, func(ctx context.Context) (bool, error) {
		for _, node := range nodes {
			mirrorPodName := fmt.Sprintf("%s-%s", vaultStaticPodName, node.Name)
			_, err := kubeClient.CoreV1().Pods(d.namespace).Get(ctx, mirrorPodName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
			t.Logf("Mirror pod %s/%s still exists", d.namespace, mirrorPodName)
			return false, nil
		}
		return true, nil
	})
}
