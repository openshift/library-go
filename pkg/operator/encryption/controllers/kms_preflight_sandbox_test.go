package controllers

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestComputeEncryptionConfigSecretDryRun_FirstKMSKey(t *testing.T) {
	instanceName := "test"
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				Type: "KMS",
				KMS: configv1.KMSPluginConfig{
					Type:  configv1.VaultKMSProvider,
					Vault: wellKnownBaseVaultConfig,
				},
			},
		},
	}

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

	requeue, secret, err := computeEncryptionConfigSecretDryRun(
		context.Background(),
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
	require.False(t, requeue)
	require.NotNil(t, secret)
	require.Equal(t, "encryption-config-"+instanceName, secret.Name)
	require.Equal(t, openshiftConfigManagedNS, secret.Namespace)

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

	for _, action := range fakeKubeClient.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" {
			t.Fatalf("live client must not be mutated, got action %#v", action)
		}
	}
}

func TestComputeEncryptionConfigSecretDryRun_RequeueWhenNotConverged(t *testing.T) {
	instanceName := "test"
	apiServer := &configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}
	fakeKubeClient := fake.NewSimpleClientset()
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})

	requeue, secret, err := computeEncryptionConfigSecretDryRun(
		context.Background(),
		instanceName,
		nil,
		provider,
		&staticEncryptionDeployerNotConverged{},
		fakeOperatorClient,
		fakeConfigClient.ConfigV1().APIServers(),
		fakeKubeClient.CoreV1(),
		metav1.ListOptions{},
	)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Nil(t, secret)
}

func TestComputeEncryptionConfigSecretDryRun_ExistingKeysPlusProviderChange(t *testing.T) {
	instanceName := "test"
	grs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	existingKey := encryptiontesting.CreateMigratedEncryptionKeySecretWithKMSPluginConfig(instanceName, grs, 1, metav1.Now().Time)

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

	requeue, secret, err := computeEncryptionConfigSecretDryRun(
		context.Background(),
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
	require.False(t, requeue)
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
}

func TestRewritePreflightWriteKeyEndpoint(t *testing.T) {
	secret, err := encryptiondata.ToSecret(openshiftConfigManagedNS, "encryption-config-test", &encryptiondata.Config{
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

func TestComputeEncryptionConfigSecretDryRun_KeyNotNeeded(t *testing.T) {
	instanceName := "test"
	grs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	existingKey := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig(instanceName, grs, 1)

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				Type: "KMS",
				KMS:  encryptiontesting.DefaultKMSPluginConfig,
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

	requeue, secret, err := computeEncryptionConfigSecretDryRun(
		context.Background(),
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
	require.False(t, requeue)
	require.NotNil(t, secret)

	cfg, err := encryptiondata.FromSecret(secret)
	require.NoError(t, err)
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
			if strings.Contains(providerCfg.KMS.Endpoint, "kms-1.sock") {
				t.Fatalf("existing write-key endpoint must be rewritten, got %q", providerCfg.KMS.Endpoint)
			}
		}
	}
	require.True(t, foundPreflightEndpoint, "expected write-key KMS endpoint rewritten to %s", preflightKMSSocketEndpoint)
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
