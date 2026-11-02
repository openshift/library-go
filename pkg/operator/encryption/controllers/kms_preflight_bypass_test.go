package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/clock"
)

func newTestEncryptionOperatorClient(disabled bool) v1helpers.OperatorClient {
	return v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{
		ManagementState:            operatorv1.Managed,
		UnsupportedConfigOverrides: runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{"encryption":{"disableKMSPreflight":%t}}`, disabled))},
	}, &operatorv1.OperatorStatus{}, nil)
}

func TestKMSPreflightDisabled(t *testing.T) {
	for _, tc := range []struct {
		name, raw     string
		want, wantErr bool
	}{
		{name: "absent"},
		{name: "false", raw: `{"encryption":{"disableKMSPreflight":false}}`},
		{name: "true", raw: `{"encryption":{"disableKMSPreflight":true}}`, want: true},
		{name: "null", raw: `{"encryption":{"disableKMSPreflight":null}}`},
		{name: "wrong type", raw: `{"encryption":{"disableKMSPreflight":"true"}}`, wantErr: true},
		{name: "invalid JSON", raw: `{`, wantErr: true},
		{name: "nested setting is ignored", raw: `{"oauthAPIServer":{"encryption":{"disableKMSPreflight":true}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{UnsupportedConfigOverrides: runtime.RawExtension{Raw: []byte(tc.raw)}}, &operatorv1.OperatorStatus{}, nil)
			got, err := kmsPreflightDisabled(c)
			require.Equal(t, tc.wantErr, err != nil)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestKMSPreflightBypassedKeyCreation(t *testing.T) {
	ctx := context.Background()
	plugin := encryptiontesting.DefaultKMSPluginConfig
	cfg, err := newKMSProviderConfig(plugin, 0)
	require.NoError(t, err)
	client := fake.NewSimpleClientset(
		encryptiontesting.CreateVaultAppRoleSecret("vault-approle-secret", "role", "secret"),
		encryptiontesting.CreateVaultCABundleConfigMap("vault-ca-bundle", "ca"),
	)
	// Nil status provider proves bypass does not require preflight status.
	c := &keyController{instanceName: "test", operatorClient: newTestEncryptionOperatorClient(true), unsupportedConfigPrefix: []string{"oauthAPIServer"}, secretClient: client.CoreV1(), configMapClient: client.CoreV1()}
	secret, ready, err := c.generateKeySecret(ctx, 1, state.KMS, plugin, cfg, "", "")
	require.NoError(t, err)
	require.True(t, ready)
	key, err := secrets.ToKeyState(secret)
	require.NoError(t, err)
	require.Equal(t, state.RemoteKeyState{}, key.RemoteKey())

	// Removing the override restores the existing gate and hash/cache behavior.
	spec, _, _, err := c.operatorClient.GetOperatorState()
	require.NoError(t, err)
	spec.UnsupportedConfigOverrides.Raw = nil
	status := &fakeKMSStatusProvider{}
	c.encryptionStatusProvider = status
	_, ready, err = c.generateKeySecret(ctx, 1, state.KMS, plugin, cfg, "", "")
	require.NoError(t, err)
	require.False(t, ready)
	require.NotEmpty(t, status.status.Preflight.ObservedConfigHash)

	// Bypassing still requires valid referenced credentials.
	spec.UnsupportedConfigOverrides.Raw = []byte(`{"encryption":{"disableKMSPreflight":true}}`)
	require.NoError(t, client.CoreV1().Secrets(openshiftConfigNS).Delete(ctx, "vault-approle-secret", metav1.DeleteOptions{}))
	_, _, err = c.generateKeySecret(ctx, 2, state.KMS, plugin, cfg, "", "")
	require.Error(t, err)
}

func TestKMSPreflightBypassCleanup(t *testing.T) {
	client := newTestEncryptionOperatorClient(true)
	deployer := &fakeDeployer{cleanupErr: fmt.Errorf("delete forbidden")}
	statusProvider := &fakeKMSStatusProvider{
		status: operatorv1.KMSEncryptionStatus{
			Preflight: operatorv1.KMSPreflightCheck{
				ObservedConfigHash: "stale-hash",
				Result: operatorv1.KMSPreflightResult{
					Status:     operatorv1.KMSPreflightResultFailed,
					ConfigHash: "stale-hash",
				},
			},
		},
	}
	c := &kmsPreflightController{
		controllerInstanceName:   "test",
		operatorClient:           client,
		deployer:                 deployer,
		dirtyDeployer:            true,
		provider:                 newTestProvider(nil),
		preconditionsFulfilledFn: alwaysFulfilledPreconditions,
		encryptionStatusProvider: statusProvider,
	}
	// Other dependencies are nil: bypass must precede config computation.
	recorder := events.NewInMemoryRecorder("test", clock.RealClock{})
	syncCtx := factory.NewSyncContext("test", recorder)
	require.ErrorContains(t, c.sync(context.Background(), syncCtx), "delete forbidden")
	deployer.cleanupErr = nil
	require.NoError(t, c.sync(context.Background(), syncCtx))
	require.NoError(t, c.sync(context.Background(), syncCtx))
	require.Equal(t, 2, deployer.cleanupCount)
	require.False(t, deployer.deployed)
	require.Equal(t, operatorv1.KMSPreflightCheck{}, statusProvider.status.Preflight)
	_, status, _, err := client.GetOperatorState()
	require.NoError(t, err)
	for _, name := range []string{"EncryptionKMSPreflightControllerDegraded", "EncryptionKMSPreflightControllerProgressing"} {
		condition := v1helpers.FindOperatorCondition(status.Conditions, name)
		require.Equal(t, operatorv1.ConditionFalse, condition.Status)
		require.Equal(t, "KMSPreflightDisabled", condition.Reason)
	}

	// Re-enabling preflight after bypass must not resurface the old failure.
	c.apiServerClient = configv1clientfake.NewSimpleClientset(newKMSVaultAPIServer()).ConfigV1().APIServers()
	spec, _, _, err := client.GetOperatorState()
	require.NoError(t, err)
	spec.UnsupportedConfigOverrides.Raw = nil
	require.NoError(t, c.sync(context.Background(), syncCtx))
	require.False(t, deployer.deployed)
	_, status, _, err = client.GetOperatorState()
	require.NoError(t, err)
	for _, name := range []string{"EncryptionKMSPreflightControllerDegraded", "EncryptionKMSPreflightControllerProgressing"} {
		condition := v1helpers.FindOperatorCondition(status.Conditions, name)
		require.Equal(t, operatorv1.ConditionFalse, condition.Status)
	}
}

func TestKMSBypassRemoteKeyBootstrap(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for _, tc := range []struct {
		name       string
		reports    []operatorv1.KMSPluginHealthReport
		wantTarget string
	}{
		{name: "missing"},
		{name: "stale", reports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "new", LastCheckedTime: metav1.NewTime(now.Add(-time.Hour))}}},
		{name: "wrong key", reports: []operatorv1.KMSPluginHealthReport{{KeyID: "2", RemoteKeyID: "new", LastCheckedTime: metav1.NewTime(now)}}},
		{name: "failed", reports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "new", Status: operatorv1.KMSPluginHealthStatusUnhealthy, LastCheckedTime: metav1.NewTime(now)}}},
		{name: "conflicting", reports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "new", LastCheckedTime: metav1.NewTime(now)}, {KeyID: "3", RemoteKeyID: "other", LastCheckedTime: metav1.NewTime(now)}}},
		{name: "converged", wantTarget: "new", reports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "new", LastCheckedTime: metav1.NewTime(now)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), []schema.GroupResource{{Resource: "secrets"}}, "3")
			c, client, current := setupRemoteKeyReconcile(t, secret, operatorv1.KMSEncryptionStatus{HealthReports: tc.reports})
			require.NoError(t, c.reconcileRemoteKeyRotation(ctx, client.CoreV1(), secret.Name, current))
			got, err := client.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
			require.NoError(t, err)
			rk, err := secrets.ReadRemoteKeyStateFromSecret(got)
			require.NoError(t, err)
			require.Equal(t, tc.wantTarget, rk.TargetRemoteKeyID)
			require.Equal(t, tc.wantTarget, rk.MigratedRemoteKeyID)
		})
	}
}
