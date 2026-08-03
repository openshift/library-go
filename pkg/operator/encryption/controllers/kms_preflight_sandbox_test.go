package controllers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestComputeEncryptionConfigSecretInTempNamespace_FirstKMSKey(t *testing.T) {
	instanceName := "test"
	configHash := "cuZm_g=="
	apiServer := apiServerWithWellKnownVaultKMS()

	fakeKubeClient := fake.NewSimpleClientset(&wellKnownBaseSecret, &wellKnownBaseConfigMap)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})
	selector := metav1.ListOptions{LabelSelector: "encryption.apiserver.operator.openshift.io/component=" + instanceName}

	secret, err := computeEncryptionConfigSecretInTempNamespace(
		context.Background(),
		configHash,
		instanceName,
		nil,
		provider,
		&staticEncryptionDeployer{},
		fakeOperatorClient,
		fakeConfigClient.ConfigV1().APIServers(),
		fakeKubeClient.CoreV1(),
		selector,
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.Equal(t, "encryption-config-"+instanceName, secret.Name)

	cfg, err := encryptiondata.FromSecret(secret)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Encryption)
	require.Contains(t, cfg.KMSPlugins, "1")

	foundPreflightEndpoint := false
	for _, resource := range cfg.Encryption.Resources {
		for _, providerCfg := range resource.Providers {
			if providerCfg.KMS == nil {
				continue
			}
			if providerCfg.KMS.Endpoint == preflightKMSSocketEndpoint {
				foundPreflightEndpoint = true
			}
		}
	}
	require.True(t, foundPreflightEndpoint, "expected write-key KMS endpoint rewritten to %s", preflightKMSSocketEndpoint)

	// Production key namespace must remain untouched.
	liveKeys, err := secrets.ListKeySecrets(context.Background(), fakeKubeClient.CoreV1(), selector)
	require.NoError(t, err)
	require.Empty(t, liveKeys)

	tempNS := preflightTempNamespaceName(configHash)
	_, err = fakeKubeClient.CoreV1().Namespaces().Get(context.Background(), tempNS, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err), "expected temp namespace cleaned up")

	// Operator degraded condition must not be written by the temp-namespace run.
	_, status, _, err := fakeOperatorClient.GetOperatorState()
	require.NoError(t, err)
	for _, c := range status.Conditions {
		require.NotEqual(t, "EncryptionKeyControllerDegraded", c.Type)
		require.NotEqual(t, "EncryptionStateControllerDegraded", c.Type)
	}
}

func TestComputeEncryptionConfigSecretInTempNamespace_WorksWhenNotConverged(t *testing.T) {
	instanceName := "test"
	configHash := "not-converged"
	apiServer := apiServerWithWellKnownVaultKMS()

	fakeKubeClient := fake.NewSimpleClientset(&wellKnownBaseSecret, &wellKnownBaseConfigMap)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})
	selector := metav1.ListOptions{LabelSelector: "encryption.apiserver.operator.openshift.io/component=" + instanceName}

	secret, err := computeEncryptionConfigSecretInTempNamespace(
		context.Background(),
		configHash,
		instanceName,
		nil,
		provider,
		&staticEncryptionDeployerNotConverged{},
		fakeOperatorClient,
		fakeConfigClient.ConfigV1().APIServers(),
		fakeKubeClient.CoreV1(),
		selector,
	)
	require.NoError(t, err)
	require.NotNil(t, secret)

	cfg, err := encryptiondata.FromSecret(secret)
	require.NoError(t, err)
	require.Contains(t, cfg.KMSPlugins, "1")
}

func TestComputeEncryptionConfigSecretInTempNamespace_ExistingKeysPlusProviderChange(t *testing.T) {
	instanceName := "test"
	configHash := "provider-change"
	grs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	existingKey := encryptiontesting.CreateMigratedEncryptionKeySecretWithKMSPluginConfig(instanceName, grs, 1, time.Now())

	changedPlugin := encryptiontesting.DefaultKMSPluginConfig
	changedPlugin.Vault.VaultAddress = "https://other-vault.example.com"

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				Type: "KMS",
				KMS:  changedPlugin,
			},
		},
	}

	vaultSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-approle-secret", Namespace: "openshift-config"},
		Data: map[string][]byte{
			"role-id":   []byte("role"),
			"secret-id": []byte("secret"),
		},
	}
	vaultCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
		Data:       map[string]string{"ca-bundle.crt": "ca"},
	}

	fakeKubeClient := fake.NewSimpleClientset(existingKey, vaultSecret, vaultCA)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	provider := newTestProvider(grs)
	selector := metav1.ListOptions{LabelSelector: "encryption.apiserver.operator.openshift.io/component=" + instanceName}

	secret, err := computeEncryptionConfigSecretInTempNamespace(
		context.Background(),
		configHash,
		instanceName,
		nil,
		provider,
		&staticEncryptionDeployer{},
		fakeOperatorClient,
		fakeConfigClient.ConfigV1().APIServers(),
		fakeKubeClient.CoreV1(),
		selector,
	)
	require.NoError(t, err)
	require.NotNil(t, secret)

	cfg, err := encryptiondata.FromSecret(secret)
	require.NoError(t, err)
	require.Contains(t, cfg.KMSPlugins, "2")

	var sawWriteKey, sawOldKey bool
	for _, resource := range cfg.Encryption.Resources {
		for _, providerCfg := range resource.Providers {
			if providerCfg.KMS == nil {
				continue
			}
			switch providerCfg.KMS.Endpoint {
			case preflightKMSSocketEndpoint:
				sawWriteKey = true
			case "unix:///var/run/kmsplugin/kms-1.sock":
				sawOldKey = true
			case "unix:///var/run/kmsplugin/kms-2.sock":
				t.Fatalf("write-key endpoint must be rewritten away from per-key socket, got %q", providerCfg.KMS.Endpoint)
			}
		}
	}
	require.True(t, sawWriteKey, "expected write-key endpoint rewritten to %s", preflightKMSSocketEndpoint)
	require.True(t, sawOldKey, "expected old key endpoint left on per-key socket")

	// Live production keys must still be only the original key.
	liveKeys, err := secrets.ListKeySecrets(context.Background(), fakeKubeClient.CoreV1(), selector)
	require.NoError(t, err)
	require.Len(t, liveKeys, 1)
	require.Equal(t, existingKey.Name, liveKeys[0].Name)
}

func TestRewritePreflightWriteKeyEndpoint(t *testing.T) {
	secret, err := encryptiondata.ToSecret(secrets.EncryptionKeysNamespace, "encryption-config-test", &encryptiondata.Config{
		Encryption: &apiserverconfigv1.EncryptionConfiguration{
			Resources: []apiserverconfigv1.ResourceConfiguration{{
				Resources: []string{"secrets"},
				Providers: []apiserverconfigv1.ProviderConfiguration{
					{KMS: &apiserverconfigv1.KMSConfiguration{Name: "2_secrets", Endpoint: "unix:///var/run/kmsplugin/kms-2.sock"}},
					{KMS: &apiserverconfigv1.KMSConfiguration{Name: "1_secrets", Endpoint: "unix:///var/run/kmsplugin/kms-1.sock"}},
				},
			}},
		},
	})
	require.NoError(t, err)

	rewritten, err := rewritePreflightWriteKeyEndpoint(secret, 2)
	require.NoError(t, err)
	cfg, err := encryptiondata.FromSecret(rewritten)
	require.NoError(t, err)
	require.Equal(t, preflightKMSSocketEndpoint, cfg.Encryption.Resources[0].Providers[0].KMS.Endpoint)
	require.Equal(t, "unix:///var/run/kmsplugin/kms-1.sock", cfg.Encryption.Resources[0].Providers[1].KMS.Endpoint)

	_, err = rewritePreflightWriteKeyEndpoint(secret, 99)
	require.Error(t, err)
	require.Contains(t, err.Error(), `write-key KMS provider with name prefix "99_" not found`)
}

func TestPreflightTempNamespaceName(t *testing.T) {
	require.Equal(t, "kms-preflight-cuzm-g", preflightTempNamespaceName("cuZm_g=="))
	require.Equal(t, "kms-preflight-unknown", preflightTempNamespaceName("==="))
	require.LessOrEqual(t, len(preflightTempNamespaceName(strings.Repeat("a", 100))), 63)
}

func TestCleanupPreflightTempNamespaces(t *testing.T) {
	ns1 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "kms-preflight-one",
		Labels: map[string]string{preflightTempNamespaceLabel: "true"},
	}}
	ns2 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "kms-preflight-two",
		Labels: map[string]string{preflightTempNamespaceLabel: "true"},
	}}
	unrelated := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config"}}
	fakeKubeClient := fake.NewSimpleClientset(ns1, ns2, unrelated)

	require.NoError(t, cleanupPreflightTempNamespaces(context.Background(), fakeKubeClient.CoreV1()))

	_, err := fakeKubeClient.CoreV1().Namespaces().Get(context.Background(), ns1.Name, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	_, err = fakeKubeClient.CoreV1().Namespaces().Get(context.Background(), ns2.Name, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	_, err = fakeKubeClient.CoreV1().Namespaces().Get(context.Background(), unrelated.Name, metav1.GetOptions{})
	require.NoError(t, err)
}

type staticEncryptionDeployer struct {
	secret *corev1.Secret
}

func (d *staticEncryptionDeployer) DeployedEncryptionConfigSecret(_ context.Context) (*corev1.Secret, bool, error) {
	return d.secret, true, nil
}

func (d *staticEncryptionDeployer) AddEventHandler(_ cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return nil, nil
}

func (d *staticEncryptionDeployer) HasSynced() bool { return true }

type staticEncryptionDeployerNotConverged struct{}

func (d *staticEncryptionDeployerNotConverged) DeployedEncryptionConfigSecret(context.Context) (*corev1.Secret, bool, error) {
	return nil, false, nil
}

func (d *staticEncryptionDeployerNotConverged) AddEventHandler(cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return nil, nil
}

func (d *staticEncryptionDeployerNotConverged) HasSynced() bool { return true }
