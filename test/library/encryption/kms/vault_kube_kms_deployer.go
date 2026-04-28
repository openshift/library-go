package kms

import (
	"bytes"
	"context"
	"fmt"
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

const (
	// WellKnownVaultNamespace is the default namespace where Vault runs.
	WellKnownVaultNamespace = "vault-kms"

	// WellKnownVaultImage is the default HashiCorp Vault Enterprise image.
	WellKnownVaultImage = "docker.io/hashicorp/vault-enterprise:2.0.0-ent"

	// WellKnownVaultServiceName is the name of the Vault service.
	WellKnownVaultServiceName = "vault"

	// DefaultVaultReplicas is the default number of Vault replicas to deploy.
	DefaultVaultReplicas = 1

	// VaultTransitMount is the default mount path for the transit secret engine.
	VaultTransitMount = "transit"

	// VaultTransitKeyName is the default key name in the transit engine.
	VaultTransitKeyName = "kubernetes-encryption-key"

	// vaultCredentialsSecretName is the name of the Secret created by the
	// init container with the AppRole credentials and root token.
	vaultCredentialsSecretName = "vault-credentials"

	vaultPollTimeout = 5 * time.Minute
)

// vaultSharedManifestFiles are applied via ApplyDirectly before the Deployment.
// Order matters: namespace first, then RBAC, then configmap and service.
var vaultSharedManifestFiles = []string{
	"vault_namespace.yaml",
	"vault_serviceaccount.yaml",
	"vault_scc_rolebinding.yaml",
	"vault_role.yaml",
	"vault_role_binding.yaml",
	"vault_configmap.yaml",
	"vault_service.yaml",
}

var vaultDeploymentManifestFile = "vault_deployment.yaml"

// VaultConfig holds the configuration for Vault deployment.
type VaultConfig struct {
	Namespace string
	Image     string
	Replicas  int
}

// vaultTemplateData holds the template variables for Vault YAML manifests.
type vaultTemplateData struct {
	Namespace string
	Image     string
	Replicas  int
}

// VaultDeployer manages the deployment and lifecycle of HashiCorp Vault Enterprise
// for KMS encryption testing. All init/unseal/configure logic runs inside the pod
// as an init container; the Go deployer only applies manifests and reads results.
type VaultDeployer struct {
	config     *VaultConfig
	kubeClient kubernetes.Interface
	t          testing.TB
}

// NewVaultDeployer creates a new VaultDeployer with the given configuration.
func NewVaultDeployer(t testing.TB, kubeClient kubernetes.Interface, config *VaultConfig) *VaultDeployer {
	t.Helper()

	if config == nil {
		config = &VaultConfig{}
	}
	if config.Namespace == "" {
		config.Namespace = WellKnownVaultNamespace
	}
	if config.Image == "" {
		config.Image = WellKnownVaultImage
	}
	if config.Replicas == 0 {
		config.Replicas = DefaultVaultReplicas
	}

	return &VaultDeployer{
		config:     config,
		kubeClient: kubeClient,
		t:          t,
	}
}

// Deploy deploys HashiCorp Vault Enterprise and waits for it to be fully
// initialized, unsealed, and configured for KMS testing.
//
// The VAULT_LICENSE environment variable must be set with the Vault Enterprise
// license. The deployer creates a K8s Secret from it, which is mounted into
// the Vault pod. An init container handles initialization, unsealing, transit
// engine setup, and AppRole configuration. Credentials are written to the
// "vault-credentials" Secret by the init container.
func (d *VaultDeployer) Deploy(ctx context.Context) error {
	d.t.Helper()
	d.t.Logf("Deploying Vault Enterprise in namespace %q (replicas: %d)", d.config.Namespace, d.config.Replicas)

	if err := d.applyManifests(ctx); err != nil {
		return fmt.Errorf("failed to apply manifests: %w", err)
	}

	if err := d.waitForDeploymentReady(ctx); err != nil {
		return fmt.Errorf("vault deployment not ready: %w", err)
	}

	if err := d.readCredentials(ctx); err != nil {
		return fmt.Errorf("failed to read vault credentials: %w", err)
	}

	return nil
}

// applyManifests creates the license secret from VAULT_LICENSE env var and
// applies all static Vault Kubernetes manifests.
func (d *VaultDeployer) applyManifests(ctx context.Context) error {
	d.t.Helper()

	templateData := vaultTemplateData{
		Namespace: d.config.Namespace,
		Image:     d.config.Image,
		Replicas:  d.config.Replicas,
	}

	recorder := events.NewInMemoryRecorder("vault-deployer", clock.RealClock{})
	assetFunc := wrapVaultAssetWithTemplateData(templateData)

	clientHolder := resourceapply.NewKubeClientHolder(d.kubeClient)
	results := resourceapply.ApplyDirectly(ctx, clientHolder, recorder, resourceapply.NewResourceCache(), assetFunc, vaultSharedManifestFiles...)
	for _, result := range results {
		if result.Error != nil {
			return result.Error
		}
		d.t.Logf("Applied %s (changed=%v)", result.File, result.Changed)
	}

	if err := d.createLicenseSecret(ctx); err != nil {
		return fmt.Errorf("failed to create license secret: %w", err)
	}

	rawDeployment, err := assetFunc(vaultDeploymentManifestFile)
	if err != nil {
		return fmt.Errorf("failed to read deployment manifest: %w", err)
	}
	deployment := resourceread.ReadDeploymentV1OrDie(rawDeployment)
	_, changed, err := resourceapply.ApplyDeployment(ctx, d.kubeClient.AppsV1(), recorder, deployment, -1)
	if err != nil {
		return fmt.Errorf("failed to apply deployment: %w", err)
	}
	d.t.Logf("Applied %s (changed=%v)", vaultDeploymentManifestFile, changed)

	return nil
}

// createLicenseSecret creates a Kubernetes Secret from the VAULT_LICENSE env var.
func (d *VaultDeployer) createLicenseSecret(ctx context.Context) error {
	d.t.Helper()

	license := os.Getenv("VAULT_LICENSE")
	if license == "" {
		d.t.Logf("VAULT_LICENSE env var not set, skipping license secret creation")
		return nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-license",
			Namespace: d.config.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"license": []byte(license),
		},
	}

	_, err := d.kubeClient.CoreV1().Secrets(d.config.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			d.t.Logf("License secret already exists, updating")
			_, err = d.kubeClient.CoreV1().Secrets(d.config.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
			return err
		}
		return err
	}
	d.t.Logf("Created vault-license secret from VAULT_LICENSE env var")
	return nil
}

// waitForDeploymentReady waits for the Vault Deployment to have all replicas
// ready, which implies the init container (vault-setup) has completed.
func (d *VaultDeployer) waitForDeploymentReady(ctx context.Context) error {
	d.t.Helper()
	d.t.Logf("Waiting for Vault deployment to be ready...")

	return wait.PollUntilContextTimeout(ctx, 2*time.Second, vaultPollTimeout, true, func(ctx context.Context) (bool, error) {
		dep, err := d.kubeClient.AppsV1().Deployments(d.config.Namespace).Get(ctx, "vault", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		desired := int32(d.config.Replicas)
		d.t.Logf("Vault deployment: desired=%d ready=%d available=%d",
			desired, dep.Status.ReadyReplicas, dep.Status.AvailableReplicas)
		return dep.Status.ReadyReplicas >= desired, nil
	})
}

// readCredentials reads the vault-credentials Secret created by the init
// container and populates the VaultConfig with AppRole credentials.
func (d *VaultDeployer) readCredentials(ctx context.Context) error {
	d.t.Helper()
	d.t.Logf("Reading vault credentials from secret %s/%s", d.config.Namespace, vaultCredentialsSecretName)

	var secret *corev1.Secret
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		var getErr error
		secret, getErr = d.kubeClient.CoreV1().Secrets(d.config.Namespace).Get(ctx, vaultCredentialsSecretName, metav1.GetOptions{})
		if getErr != nil {
			if apierrors.IsNotFound(getErr) {
				return false, nil
			}
			return false, getErr
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for %s secret: %w", vaultCredentialsSecretName, err)
	}

	if _, ok := secret.Data["role-id"]; !ok {
		return fmt.Errorf("vault-credentials secret missing role-id")
	}
	if _, ok := secret.Data["secret-id"]; !ok {
		return fmt.Errorf("vault-credentials secret missing secret-id")
	}

	d.t.Logf("Vault AppRole credentials loaded from secret")
	return nil
}

// wrapVaultAssetWithTemplateData returns an AssetFunc that templates Vault YAML with the given data.
func wrapVaultAssetWithTemplateData(data vaultTemplateData) resourceapply.AssetFunc {
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
