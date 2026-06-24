package pluginlifecycle

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

// defaultStaticPodKubeconfig is reused from the cert-syncer kubeconfig because
// in-cluster config does not work on host-network static pods (kubernetes.default.svc
// does not resolve). This matches the pattern used by the startup monitor.
// TODO: move to a dedicated least-privilege kubeconfig once available.
const defaultStaticPodKubeconfig = "/etc/kubernetes/static-pod-resources/configmaps/kube-apiserver-cert-syncer-kubeconfig/kubeconfig"

// applyHealthReporter injects the health reporter sidecar. It is opt-in via
// WithHealthReporter. Plugin lifecycle callers enable it; preflight callers
// do not, since they only verify plugin reachability.
func (b *KMSPluginBuilder) applyHealthReporter(podSpec *corev1.PodSpec, sockets []string) error {
	if b.healthReporter == nil {
		return nil
	}

	if len(sockets) == 0 {
		return nil
	}

	if b.healthReporter.name == "" || b.healthReporter.operatorBinary == "" || b.healthReporter.image == "" || b.healthReporter.subcommand == "" {
		return fmt.Errorf("health reporter name, operatorBinary, image and subcommand are required when WithHealthReporter is used")
	}

	b.healthReporter.sockets = sockets
	if b.staticPod {
		b.healthReporter.kubeconfig = defaultStaticPodKubeconfig
	}

	if err := ensureSidecarContainer(podSpec, b.healthReporter); err != nil {
		return err
	}

	if err := ensureSocketVolume(podSpec); err != nil {
		return err
	}

	socketMount := corev1.VolumeMount{Name: kmsPluginSocketVolumeName, MountPath: kmsPluginSocketMountPath, ReadOnly: true}
	if err := ensureVolumeMountInContainer(podSpec.InitContainers, b.healthReporter.Name(), socketMount); err != nil {
		return err
	}

	if b.staticPod {
		resourceDirMount := corev1.VolumeMount{Name: resourceDirVolumeName, MountPath: resourcesDir, ReadOnly: true}
		if err := ensureVolumeMountInContainer(podSpec.InitContainers, b.healthReporter.Name(), resourceDirMount); err != nil {
			return err
		}
		if err := setRunAsRoot(podSpec.InitContainers, b.healthReporter.Name()); err != nil {
			return err
		}
	}

	return nil
}

type healthReporter struct {
	name           string
	operatorBinary string
	subcommand     string
	image          string
	sockets        []string
	kubeconfig     string
}

func (h *healthReporter) Name() string {
	return h.name
}

func (h *healthReporter) BuildSidecarContainer() (corev1.Container, error) {
	if len(h.sockets) == 0 {
		return corev1.Container{}, fmt.Errorf("at least one KMS socket is required")
	}

	args := []string{
		fmt.Sprintf("--kms-sockets=%s", strings.Join(h.sockets, ",")),
		"--node-name=$(NODE_NAME)",
	}
	if h.kubeconfig != "" {
		args = append(args, fmt.Sprintf("--kubeconfig=%s", h.kubeconfig))
	}

	return corev1.Container{
		Name:                     h.Name(),
		Image:                    h.image,
		Command:                  []string{h.operatorBinary, h.subcommand},
		Args:                     args,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		// NODE_NAME is expanded in --node-name=$(NODE_NAME) above so the
		// health reporter can identify which node's health it is reporting.
		Env: []corev1.EnvVar{
			{
				Name: "NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
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
	}, nil
}
