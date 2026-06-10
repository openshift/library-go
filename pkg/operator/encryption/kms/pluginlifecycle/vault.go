package pluginlifecycle

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

// newVaultSidecarProvider creates a Vault sidecar provider from the given KMS plugin data.
// It assumes the input data has been already been validated.
func newVaultSidecarProvider(name, keyID, udsPath string, vaultConfig configv1.VaultKMSPluginConfig, creds *credentialResolver, unsupportedConfig []byte) (*vault, error) {
	secretName := vaultConfig.Authentication.AppRole.Secret.Name
	if secretName == "" {
		return nil, fmt.Errorf("vault AppRole authentication secret name cannot be empty")
	}

	roleID, err := creds.Value(secretName, "role-id")
	if err != nil {
		return nil, err
	}

	if roleID == "" {
		return nil, fmt.Errorf("role ID cannot be empty")
	}

	secretIDPath, err := creds.FilePath(secretName, "secret-id")
	if err != nil {
		return nil, err
	}

	if secretIDPath == "" {
		return nil, fmt.Errorf("secret ID path cannot be empty")
	}

	kmsConfig, err := parseUnsupportedKMSConfig(unsupportedConfig)
	if err != nil {
		return nil, err
	}

	return &vault{
		name:         name,
		keyID:        keyID,
		udsPath:      udsPath,
		config:       vaultConfig,
		roleID:       roleID,
		secretIDPath: secretIDPath,
		logLevel:     kmsConfig.Encryption.KMS.Vault.LogLevel,
	}, nil
}

// vault implements SidecarProvider for HashiCorp Vault KMS.
type vault struct {
	name         string
	keyID        string
	udsPath      string
	config       configv1.VaultKMSPluginConfig
	roleID       string
	secretIDPath string
	logLevel     string
}

// Name returns the sidecar name appended by the key id.
func (v *vault) Name() string {
	return fmt.Sprintf("%s-%s", v.name, v.keyID)
}

// BuildSidecarContainer returns a container spec for the Vault KMS plugin sidecar
// configured with the Vault address, namespace, transit mount, and transit key.
func (v *vault) BuildSidecarContainer() (corev1.Container, error) {
	// Required API fields: always set.
	args := []string{
		fmt.Sprintf("-listen-address=%s", v.udsPath),
		fmt.Sprintf("-vault-address=%s", v.config.VaultAddress),
		fmt.Sprintf("-transit-mount=%s", v.config.TransitMount),
		fmt.Sprintf("-transit-key=%s", v.config.TransitKey),
		fmt.Sprintf("-approle-role-id=%s", v.roleID),
		fmt.Sprintf("-approle-secret-id-path=%s", v.secretIDPath),
	}

	// Optional fields: only pass non-empty values.
	if v.config.VaultNamespace != "" {
		args = append(args, fmt.Sprintf("-vault-namespace=%s", v.config.VaultNamespace))
	}
	if v.logLevel != "" {
		args = append(args, fmt.Sprintf("-log-level=%s", v.logLevel))
	}

	// Temporary workarounds. These should go away as we progress with the feature.
	args = append(args,
		// TODO: remove before GA once the CA bundle is wired into the encryption config secret.
		"-tls-skip-verify=true",
		// TODO: remove once we support scraping metrics from each KMS plugin sidecar independently.
		// Set the port to zero to disable metrics serving.
		// Slack discussion: https://redhat-external.slack.com/archives/C09KZ5QCBUH/p1780926464635219
		"-metrics-port=0",
	)

	return corev1.Container{
		Name:            v.Name(),
		Image:           v.config.KMSPluginImage,
		Args:            args,
		ImagePullPolicy: corev1.PullIfNotPresent,
		// We place the container in InitContainers with RestartPolicyAlways so the kubelet starts it before
		// regular containers and keeps it running for the pod's lifetime.
		RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		// Vault team recommendation based on single-node OCP cluster measurements:
		// ~10 mCPU / 32-64 MiB steady state, memory peaked at ~60 MiB under 400 KEK rotations.
		// Slack discussion: https://redhat-external.slack.com/archives/C09KZ5QCBUH/p1779134070543079
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("64Mi"),
				corev1.ResourceCPU:    resource.MustParse("10m"),
			},
		},
	}, nil
}
