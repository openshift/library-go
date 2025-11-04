package kms

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// from https://github.com/flavianmissi/library-go/tree/kms-plugin-sidecars

const (
	// defaultKMSPluginImage is the default AWS KMS plugin image
	// This should be overridden by the operator with the actual image reference
	defaultKMSPluginImage = "registry.k8s.io/kms-plugin-aws:latest"

	// defaultHealthPort is the default port for the KMS plugin health endpoint
	defaultHealthPort = 8080

	// KMSContainerName is the standard name for the KMS plugin sidecar container
	KMSContainerName = "kms-plugin"

	// KMSSocketVolumeName is the standard name for the socket volume
	KMSSocketVolumeName = "kms-socket"

	// KMSCredentialsVolumeName is the standard name for the credentials volume
	KMSCredentialsVolumeName = "aws-credentials"
)

// ContainerConfig holds additional configuration beyond what's in configv1.KMSConfig
// for building the KMS plugin sidecar container
type ContainerConfig struct {
	// KMSConfig is the desired configv1.KMSConfig
	// Required
	KMSConfig *configv1.KMSConfig

	// Image is the container image for the KMS plugin
	// Required
	Image string

	// UseHostNetwork indicates if the pod uses hostNetwork: true
	// If true, the container will access AWS credentials via EC2 IMDS
	// If false, credentials must be provided via CredentialsSecretName
	UseHostNetwork bool

	// CredentialsSecretName is the name of the secret containing AWS credentials
	// Only required when UseHostNetwork is false
	// The secret should contain a key "credentials" in AWS shared credentials file format
	CredentialsSecretName string

	// SocketPath is the Unix socket path where the KMS plugin listens
	// Optional - defaults to defaultSocketPath
	SocketPath string

	// HealthPort is the port for the KMS plugin health endpoint
	// Optional - defaults to defaultHealthPort
	HealthPort int32

	// CPURequest is the CPU request for the container
	// Optional - defaults to "10m"
	CPURequest string

	// MemoryRequest is the memory request for the container
	// Optional - defaults to "50Mi"
	MemoryRequest string
}

// Validate ensures the ContainerConfig is valid
func (c *ContainerConfig) Validate() error {
	if c.Image == "" {
		return fmt.Errorf("Image is required")
	}
	if !c.UseHostNetwork && c.CredentialsSecretName == "" {
		return fmt.Errorf("CredentialsSecretName is required when UseHostNetwork is false")
	}
	return nil
}

// setDefaults sets default values for unspecified fields
func (c *ContainerConfig) setDefaults() {
	if c.SocketPath == "" {
		socket, _, err := GenerateUnixSocketPath(c.KMSConfig)
		if err != nil {
			panic(err)
		}
		c.SocketPath = socket
	}
	if c.HealthPort == 0 {
		c.HealthPort = defaultHealthPort
	}
	if c.CPURequest == "" {
		c.CPURequest = "10m"
	}
	if c.MemoryRequest == "" {
		c.MemoryRequest = "50Mi"
	}
}

// buildPluginContainer creates a corev1.Container spec for the KMS plugin sidecar
// based on the KMS configuration from openshift/api and container-specific config
func buildPluginContainer(kmsConfig *configv1.KMSConfig, containerConfig *ContainerConfig) (*corev1.Container, error) {
	if kmsConfig == nil {
		return nil, fmt.Errorf("kmsConfig cannot be nil")
	}
	if containerConfig == nil {
		return nil, fmt.Errorf("containerConfig cannot be nil")
	}

	// Validate inputs
	if err := containerConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid container config: %w", err)
	}

	// Set defaults
	containerConfig.setDefaults()

	// Currently only AWS is supported
	if kmsConfig.Type != configv1.AWSKMSProvider {
		return nil, fmt.Errorf("unsupported KMS provider type: %s (only %s is supported)", kmsConfig.Type, configv1.AWSKMSProvider)
	}
	if kmsConfig.AWS == nil {
		return nil, fmt.Errorf("AWS KMS config is required when type is AWS")
	}

	container := &corev1.Container{
		Name:  KMSContainerName,
		Image: containerConfig.Image,
		Command: []string{
			"/aws-encryption-provider",
		},
		Args: []string{
			fmt.Sprintf("--key=%s", kmsConfig.AWS.KeyARN),
			fmt.Sprintf("--region=%s", kmsConfig.AWS.Region),
			fmt.Sprintf("--listen=%s", containerConfig.SocketPath),
		},
		Ports: []corev1.ContainerPort{
			{
				Name:          "healthz",
				ContainerPort: containerConfig.HealthPort,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
			ReadOnlyRootFilesystem: ptr.To(true),
			RunAsUser:              ptr.To(int64(0)), // Required for AWS SDK credential chain
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      KMSSocketVolumeName,
				MountPath: "/var/run/kms",
			},
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/healthz",
					Port: intstr.FromInt32(containerConfig.HealthPort),
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			TimeoutSeconds:      3,
			FailureThreshold:    3,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/healthz",
					Port: intstr.FromInt32(containerConfig.HealthPort),
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       5,
			TimeoutSeconds:      3,
			FailureThreshold:    3,
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(containerConfig.CPURequest),
				corev1.ResourceMemory: resource.MustParse(containerConfig.MemoryRequest),
			},
		},
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
	}

	// Add credentials mount if not using hostNetwork
	if !containerConfig.UseHostNetwork {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "AWS_SHARED_CREDENTIALS_FILE",
			Value: "/var/run/secrets/aws/credentials",
		})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      KMSCredentialsVolumeName,
			MountPath: "/var/run/secrets/aws",
			ReadOnly:  true,
		})
	}

	return container, nil
}

// buildPluginVolumes creates the required volumes for the KMS plugin
func buildPluginVolumes(useHostNetwork bool, credentialsSecretName string, hostPath bool) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: KMSSocketVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	// For static pods using hostPath, override the socket volume
	if hostPath {
		volumes[0].VolumeSource = corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/var/run/kms",
				Type: ptr.To(corev1.HostPathDirectoryOrCreate),
			},
		}
	}

	// Add credentials volume if not using hostNetwork
	if !useHostNetwork && credentialsSecretName != "" {
		volumes = append(volumes, corev1.Volume{
			Name: KMSCredentialsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: credentialsSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  "credentials",
							Path: "credentials",
						},
					},
				},
			},
		})
	}

	return volumes
}

// AddKMSPluginToPodSpec injects the KMS plugin container and volumes into a PodSpec
// This is a convenience function that combines buildPluginContainer() and buildPluginVolumes()
func AddKMSPluginToPodSpec(
	podSpec *corev1.PodSpec,
	kmsConfig *configv1.KMSConfig,
	containerConfig *ContainerConfig,
	useHostPathForSocket bool,
) error {
	if podSpec == nil {
		return fmt.Errorf("podSpec cannot be nil")
	}

	// Create the KMS plugin container
	kmsContainer, err := buildPluginContainer(kmsConfig, containerConfig)
	if err != nil {
		return fmt.Errorf("failed to create KMS plugin container: %w", err)
	}

	// Add the container to the pod spec
	podSpec.Containers = append(podSpec.Containers, *kmsContainer)

	// Add required volumes
	volumes := buildPluginVolumes(containerConfig.UseHostNetwork, containerConfig.CredentialsSecretName, useHostPathForSocket)
	podSpec.Volumes = append(podSpec.Volumes, volumes...)

	// Mount the KMS socket in the API server container
	// Find the main API server container and add the socket mount
	for i := range podSpec.Containers {
		// Look for common API server container names
		if podSpec.Containers[i].Name == "kube-apiserver" ||
			podSpec.Containers[i].Name == "openshift-apiserver" ||
			podSpec.Containers[i].Name == "oauth-apiserver" {
			podSpec.Containers[i].VolumeMounts = append(podSpec.Containers[i].VolumeMounts, corev1.VolumeMount{
				Name:      KMSSocketVolumeName,
				MountPath: "/var/run/kms",
				ReadOnly:  true,
			})
			break
		}
	}

	return nil
}
