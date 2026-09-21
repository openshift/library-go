package kms

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	library "github.com/openshift/library-go/test/library/encryption"
)

// resolveVaultKMSPluginImage determines the vault-kube-kms plugin image to use.
// It checks SHARED_DIR because the openshift-e2e-test step ref is a widely-used
// shared ref that does not declare VAULT_KMS_PLUGIN_IMAGE in its env list.
// The vault-install step writes the image reference to a file in SHARED_DIR,
// allowing subsequent steps to pick it up without modifying the shared ref.
func resolveVaultKMSPluginImage(t testing.TB) string {
	t.Helper()
	if img := os.Getenv("VAULT_KMS_PLUGIN_IMAGE"); img != "" {
		t.Logf("Using vault KMS plugin image from VAULT_KMS_PLUGIN_IMAGE env: %s", img)
		return img
	}
	sharedDir := os.Getenv("SHARED_DIR")
	if sharedDir == "" {
		t.Fatal("SHARED_DIR environment variable is not set; cannot resolve vault KMS plugin image")
	}
	imagePath := sharedDir + "/vault-kms-plugin-image"
	data, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatalf("failed to read vault KMS plugin image from %s: %v", imagePath, err)
	}
	img := strings.TrimSpace(string(data))
	if img == "" {
		t.Fatalf("vault KMS plugin image file %s is empty", imagePath)
	}
	t.Logf("Resolved vault KMS plugin image from %s: %s", imagePath, img)
	return img
}

const (
	defaultVaultNamespace         = "vault-kms"
	defaultVaultServiceName       = "vault"
	defaultVaultPodName           = "vault-0"
	defaultVaultCredentialsSecret = "vault-credentials"
	defaultVaultAppRoleSecretName = "vault-approle-secret"
	defaultVaultConfigMapName     = "vault-ca-bundle"
	defaultVaultAddress           = "https://vault.vault-kms.svc:8200"
	defaultVaultEnterpriseNS      = "admin"
	defaultVaultKeyPath           = "transit/keys/kms-key"
	defaultAppRoleTargetNamespace = "openshift-config"
	vaultCommandTimeout           = 30 * time.Second

	// Secondary Vault instance constants for KMS-to-KMS migration testing.
	secondaryVaultNamespace         = "vault-kms-secondary"
	secondaryVaultServiceName       = "vault-secondary"
	secondaryVaultAppRoleSecretName = "vault-approle-secret-secondary"
	secondaryVaultConfigMapName     = "vault-ca-bundle-secondary"
	secondaryVaultAddress           = "https://vault-secondary.vault-kms-secondary.svc:8200"
	secondaryVaultKeyPath           = "transit/keys/kms-key-secondary"
)

// DefaultVaultEncryptionProvider returns a ready-to-use Vault KMS EncryptionProvider for e2e tests.
// It resolves the Vault Service ClusterIP at call time to avoid DNS resolution issues,
// and bundles the AppRole secret setup.
func DefaultVaultEncryptionProvider(ctx context.Context, t testing.TB) library.EncryptionProvider {
	cfg := DefaultVaultKMSPluginConfig
	vault := defaultVaultConfig.DeepCopy()
	require.NoError(t, unstructured.SetNestedField(vault.Object, resolveVaultKMSPluginImage(t), "status", "kmsPluginImage"))
	// Use the Service ClusterIP instead of DNS name because kube-apiserver pods
	// cannot resolve cluster-local Service names (they use host network DNS).
	require.NoError(t, unstructured.SetNestedField(vault.Object, getVaultServiceAddress(ctx, t, defaultVaultNamespace, defaultVaultServiceName), "spec", "vaultAddress"))
	return library.EncryptionProvider{
		APIServerEncryption: cfg,
		Setup: func(ctx context.Context, t testing.TB) {
			ensureVaultAppRoleSecret(defaultVaultNamespace, defaultVaultAppRoleSecretName)(ctx, t)
			ensureVaultKMSConfig(ctx, t, cfg.KMS.PluginConfig.Name, vault)
		},
	}
}

// DefaultVaultKMSPluginConfig is the standard Vault KMS encryption config
// used by CI e2e tests.
var DefaultVaultKMSPluginConfig = configv1.APIServerEncryption{
	Type: configv1.EncryptionTypeKMS,
	KMS:  configv1.KMSPluginConfig{PluginConfig: configv1.KMSPluginConfigReference{APIVersion: "kms.openshift.io/v1alpha1", Resource: "vaultkmsconfigs", Name: "vault"}},
}

var defaultVaultConfig = &unstructured.Unstructured{Object: map[string]interface{}{
	"apiVersion": "kms.openshift.io/v1alpha1",
	"kind":       "VaultKMSConfig",
	"spec": map[string]interface{}{
		"vaultAddress":   defaultVaultAddress,
		"vaultNamespace": defaultVaultEnterpriseNS,
		"vaultKeyPath":   defaultVaultKeyPath,
		"authentication": map[string]interface{}{
			"type": "AppRole",
			"appRole": map[string]interface{}{
				"secret": map[string]interface{}{
					"name": defaultVaultAppRoleSecretName,
				},
			},
		},
		"tls": map[string]interface{}{
			"caBundle": map[string]interface{}{
				"name": defaultVaultConfigMapName,
			},
			"serverName": fmt.Sprintf("vault.%s.svc", defaultVaultNamespace),
		},
	},
	"status": map[string]interface{}{},
}}

// SecondaryVaultKMSPluginConfig is the Vault KMS encryption config for the
// secondary Vault instance, used in KMS-to-KMS migration e2e tests.
var SecondaryVaultKMSPluginConfig = configv1.APIServerEncryption{
	Type: configv1.EncryptionTypeKMS,
	KMS:  configv1.KMSPluginConfig{PluginConfig: configv1.KMSPluginConfigReference{APIVersion: "kms.openshift.io/v1alpha1", Resource: "vaultkmsconfigs", Name: "vault-secondary"}},
}

var secondaryVaultConfig = &unstructured.Unstructured{Object: map[string]interface{}{
	"apiVersion": "kms.openshift.io/v1alpha1",
	"kind":       "VaultKMSConfig",
	"spec": map[string]interface{}{
		"vaultAddress":   secondaryVaultAddress,
		"vaultNamespace": defaultVaultEnterpriseNS,
		"vaultKeyPath":   secondaryVaultKeyPath,
		"authentication": map[string]interface{}{
			"type": "AppRole",
			"appRole": map[string]interface{}{
				"secret": map[string]interface{}{
					"name": secondaryVaultAppRoleSecretName,
				},
			},
		},
		"tls": map[string]interface{}{
			"caBundle": map[string]interface{}{
				"name": secondaryVaultConfigMapName,
			},
			"serverName": fmt.Sprintf("vault-secondary.%s.svc", secondaryVaultNamespace),
		},
	},
	"status": map[string]interface{}{},
}}

// SecondaryVaultEncryptionProvider returns a ready-to-use Vault KMS EncryptionProvider
// for the secondary Vault instance, used in KMS-to-KMS migration e2e tests.
func SecondaryVaultEncryptionProvider(ctx context.Context, t testing.TB) library.EncryptionProvider {
	cfg := SecondaryVaultKMSPluginConfig
	vault := secondaryVaultConfig.DeepCopy()
	require.NoError(t, unstructured.SetNestedField(vault.Object, resolveVaultKMSPluginImage(t), "status", "kmsPluginImage"))
	require.NoError(t, unstructured.SetNestedField(vault.Object, getVaultServiceAddress(ctx, t, secondaryVaultNamespace, secondaryVaultServiceName), "spec", "vaultAddress"))
	return library.EncryptionProvider{
		APIServerEncryption: cfg,
		Setup: func(ctx context.Context, t testing.TB) {
			ensureVaultAppRoleSecret(secondaryVaultNamespace, secondaryVaultAppRoleSecretName)(ctx, t)
			ensureVaultKMSConfig(ctx, t, cfg.KMS.PluginConfig.Name, vault)
		},
	}
}

// ensureVaultKMSConfig publishes the e2e fixture using the external CRD, which
// must be installed on the test cluster. The test image remains supplied by CI.
func ensureVaultKMSConfig(ctx context.Context, t testing.TB, name string, vault *unstructured.Unstructured) {
	t.Helper()
	spec, _, err := unstructured.NestedMap(vault.Object, "spec")
	require.NoError(t, err)
	image, _, err := unstructured.NestedString(vault.Object, "status", "kmsPluginImage")
	require.NoError(t, err)
	client := library.GetClients(t).DynamicClient.Resource(schema.GroupVersionResource{Group: "kms.openshift.io", Version: "v1alpha1", Resource: "vaultkmsconfigs"})
	err = retry.OnError(retry.DefaultRetry, func(err error) bool { return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) }, func() error {
		obj, err := client.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			obj = &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kms.openshift.io/v1alpha1", "kind": "VaultKMSConfig", "metadata": map[string]interface{}{"name": name}, "spec": spec}}
			obj, err = client.Create(ctx, obj, metav1.CreateOptions{})
		} else if err == nil {
			obj.Object["spec"] = spec
			obj, err = client.Update(ctx, obj, metav1.UpdateOptions{})
		}
		if err != nil {
			return err
		}
		if err := unstructured.SetNestedField(obj.Object, image, "status", "kmsPluginImage"); err != nil {
			return err
		}
		_, err = client.UpdateStatus(ctx, obj, metav1.UpdateOptions{})
		return err
	})
	require.NoError(t, err, "failed to apply VaultKMSConfig %s", name)
}

func ensureVaultAppRoleSecret(vaultNamespace, appRoleSecretName string) func(ctx context.Context, t testing.TB) {
	return func(ctx context.Context, t testing.TB) {
		t.Helper()
		cs := library.GetClients(t)

		creds, err := cs.Kube.CoreV1().Secrets(vaultNamespace).Get(ctx, defaultVaultCredentialsSecret, metav1.GetOptions{})
		require.NoError(t, err, "failed to read %s/%s secret (was the vault-install CI step run?)", vaultNamespace, defaultVaultCredentialsSecret)

		required := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      appRoleSecretName,
				Namespace: defaultAppRoleTargetNamespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"role-id":   creds.Data["role-id"],
				"secret-id": creds.Data["secret-id"],
			},
		}
		recorder := events.NewInMemoryRecorder("vault-approle-secret-setup", clock.RealClock{})
		_, changed, err := resourceapply.ApplySecret(ctx, cs.Kube.CoreV1(), recorder, required)
		if apierrors.IsAlreadyExists(err) {
			// Parallel Setup calls can race on Create; the first wins, others get AlreadyExists.
			t.Logf("AppRole secret %s in %s already applied by another goroutine", appRoleSecretName, defaultAppRoleTargetNamespace)
			return
		}
		require.NoError(t, err, "failed to apply AppRole secret")
		t.Logf("Applied AppRole secret %s in %s (changed=%v)", appRoleSecretName, defaultAppRoleTargetNamespace, changed)
	}
}

func ForceVaultKeyRotation() library.ForceRotationFunc {
	return RotateVaultTransitKey
}

// RotateVaultTransitKey rotates the Vault transit encryption key. All old key versions are retained.
// Reference: https://developer.hashicorp.com/vault/api-docs/secret/transit#rotate-key
// Steps:
// 1. Get initial key version
// 2. Execute 'vault write -f transit/keys/<key-name>/rotate' via oc exec
// 3. Get new key version and validate it increased
func RotateVaultTransitKey(t testing.TB, ctx context.Context) {
	t.Helper()

	initialVersion := getCurrentKeyVersion(ctx, t)
	rotateKey(ctx, t)
	newVersion := getCurrentKeyVersion(ctx, t)

	require.Greater(t, newVersion, initialVersion, "rotation failed: version did not increase (before=%d, after=%d)", initialVersion, newVersion)
}

// rotateKey executes the vault key rotation command
func rotateKey(ctx context.Context, t testing.TB) {
	t.Helper()
	commandCtx, cancel := context.WithTimeout(ctx, vaultCommandTimeout)
	defer cancel()

	// Command: vault write -f transit/keys/<key-name>/rotate
	// Reference: https://developer.hashicorp.com/vault/api-docs/secret/transit#rotate-key
	cmd := exec.CommandContext(commandCtx, "oc", "exec", defaultVaultPodName, "-n", defaultVaultNamespace, "--",
		"vault", "write", fmt.Sprintf("-namespace=%s", defaultVaultEnterpriseNS), "-f", fmt.Sprintf("%s/rotate", defaultVaultKeyPath))

	t.Logf("Executing: %s", cmd.String())
	output, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		require.NoError(t, err, "vault key rotation failed, stderr: %s", string(ee.Stderr))
	}
	require.NoError(t, err, "vault key rotation failed")
	t.Logf("Command output: %s", string(output))
}

// getCurrentKeyVersion retrieves the current (latest) key version
func getCurrentKeyVersion(ctx context.Context, t testing.TB) int {
	t.Helper()
	commandCtx, cancel := context.WithTimeout(ctx, vaultCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(commandCtx, "oc", "exec", defaultVaultPodName, "-n", defaultVaultNamespace, "--",
		"vault", "read", fmt.Sprintf("-namespace=%s", defaultVaultEnterpriseNS), "-field=latest_version", defaultVaultKeyPath)

	t.Logf("Executing: %s", cmd.String())
	output, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		require.NoError(t, err, "failed to read key version, stderr: %s", string(ee.Stderr))
	}
	require.NoError(t, err, "failed to read key version")
	t.Logf("Command output: %s", string(output))

	version, err := strconv.Atoi(strings.TrimSpace(string(output)))
	require.NoError(t, err, "failed to parse key version from output: %q", string(output))

	return version
}

// getVaultServiceAddress returns the Vault address using the Service's ClusterIP
// instead of the DNS name, reading the port and scheme from the Service spec.
func getVaultServiceAddress(ctx context.Context, t testing.TB, ns, serviceName string) string {
	t.Helper()
	cs := library.GetClients(t)

	svc, err := cs.Kube.CoreV1().Services(ns).Get(ctx, serviceName, metav1.GetOptions{})
	require.NoError(t, err, "failed to get vault Service in namespace %s", ns)
	require.NotEmpty(t, svc.Spec.ClusterIP, "vault Service has no ClusterIP")
	require.NotEmpty(t, svc.Spec.Ports, "vault Service has no ports")

	// The Vault Helm chart names the client port "https" (8200).
	var port *corev1.ServicePort
	for i := range svc.Spec.Ports {
		if svc.Spec.Ports[i].Name == "https" {
			port = &svc.Spec.Ports[i]
			break
		}
	}
	require.NotNil(t, port, "vault Service has no port named \"https\"")

	addr := fmt.Sprintf("https://%s", net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(port.Port))))
	t.Logf("Resolved Vault Service address: %s", addr)
	return addr
}

// VaultEncryptionProvider returns DefaultVaultEncryptionProvider with optional overrides.
// mutate may be nil; it receives the VaultKMSConfig unstructured used by Setup.
// For case-specific prereqs (e.g. a dedicated invalid AppRole secret), use
// VaultNegativeCase.Setup instead of mutating shared credentials.
func VaultEncryptionProvider(ctx context.Context, t testing.TB, mutate func(*unstructured.Unstructured)) library.EncryptionProvider {
	t.Helper()
	cfg := DefaultVaultKMSPluginConfig
	vault := defaultVaultConfig.DeepCopy()
	require.NoError(t, unstructured.SetNestedField(vault.Object, resolveVaultKMSPluginImage(t), "status", "kmsPluginImage"))
	require.NoError(t, unstructured.SetNestedField(vault.Object, getVaultServiceAddress(ctx, t, defaultVaultNamespace, defaultVaultServiceName), "spec", "vaultAddress"))
	if mutate != nil {
		mutate(vault)
	}
	return library.EncryptionProvider{
		APIServerEncryption: cfg,
		Setup: func(ctx context.Context, t testing.TB) {
			ensureVaultAppRoleSecret(defaultVaultNamespace, defaultVaultAppRoleSecretName)(ctx, t)
			ensureVaultKMSConfig(ctx, t, cfg.KMS.PluginConfig.Name, vault)
		},
	}
}

// EnsureInvalidVaultAppRoleSecret creates a dedicated AppRole secret with the given
// invalid secret-id (leaves the shared vault-approle-secret untouched) and deletes it on cleanup.
// Point VaultNegativeCase.Mutate at secretName.
func EnsureInvalidVaultAppRoleSecret(ctx context.Context, t testing.TB, clients library.ClientSet, secretName, invalidSecretID string) {
	t.Helper()
	require.NotEmpty(t, secretName)
	require.NotEmpty(t, invalidSecretID)
	src, err := clients.Kube.CoreV1().Secrets(defaultAppRoleTargetNamespace).Get(ctx, defaultVaultAppRoleSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, src.Data["role-id"])

	invalid := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: defaultAppRoleTargetNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"role-id":   append([]byte(nil), src.Data["role-id"]...),
			"secret-id": []byte(invalidSecretID),
		},
	}
	_, err = clients.Kube.CoreV1().Secrets(defaultAppRoleTargetNamespace).Create(ctx, invalid, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := clients.Kube.CoreV1().Secrets(defaultAppRoleTargetNamespace).Delete(cleanupCtx, secretName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("failed to delete invalid AppRole secret %s: %v", secretName, err)
		}
	})
}
