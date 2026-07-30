package controllers

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/clock"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	openshiftConfigManagedNS   = "openshift-config-managed"
	preflightKMSSocketEndpoint = "unix:///var/run/kmsplugin/kms.sock"
)

// computeEncryptionConfigSecretDryRun runs keyController.sync then stateController.sync against the
// live cluster with an in-memory write overlay, returning the encryption-config Secret those controllers
// would have applied without persisting the key or encryption-config Secrets to the real API.
// If the live encryption deployer reports !converged, requeue is true and secret is nil.
func computeEncryptionConfigSecretDryRun(
	ctx context.Context,
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
) (requeue bool, secret *corev1.Secret, err error) {
	_, converged, err := encryptionDeployer.DeployedEncryptionConfigSecret(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get deployed encryption config: %w", err)
	}
	if !converged {
		return true, nil, nil
	}

	// overlay is shared between both dry-run runs so the key secret created by
	// the key controller is visible to the state controller's List call.
	overlay, err := newDryRunSecretsGetter(coreClient)
	if err != nil {
		return false, nil, err
	}

	if err := dryRunKeyController(ctx, overlay, instanceName, unsupportedConfigPrefix, provider, encryptionDeployer, operatorClient, apiServerClient, coreClient, encryptionSecretSelector); err != nil {
		return false, nil, err
	}

	encryptionSecret, err := dryRunStateController(ctx, overlay, instanceName, provider, encryptionDeployer, operatorClient, encryptionSecretSelector)
	if err != nil {
		return false, nil, err
	}

	// The write key is the highest key ID among live + dry-run overlay secrets.
	keySecrets, err := secrets.ListKeySecrets(ctx, overlay, encryptionSecretSelector)
	if err != nil {
		return false, nil, err
	}
	var latestKeyID uint64
	foundKey := false
	for _, s := range keySecrets {
		id, ok := state.NameToKeyID(s.Name)
		if !ok {
			continue
		}
		if !foundKey || id > latestKeyID {
			latestKeyID = id
			foundKey = true
		}
	}
	if !foundKey {
		return false, nil, fmt.Errorf("no encryption key secrets found after key controller dry-run")
	}

	rewritten, err := rewritePreflightWriteKeyEndpoint(encryptionSecret, latestKeyID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to rewrite preflight KMS endpoint: %w", err)
	}
	return false, rewritten, nil
}

func dryRunKeyController(
	ctx context.Context,
	overlay *dryRunSecretsGetter,
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
) error {
	dryRunOperatorClient, err := operatorClientForDryRun(operatorClient)
	if err != nil {
		return err
	}

	c := &keyController{
		operatorClient:           dryRunOperatorClient,
		apiServerClient:          apiServerClient,
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionKey"),
		unsupportedConfigPrefix:  unsupportedConfigPrefix,
		encryptionSecretSelector: encryptionSecretSelector,
		deployer:                 encryptionDeployer,
		provider:                 provider,
		preconditionsFulfilledFn: func() (bool, error) { return true, nil },
		secretClient:             overlay,
		configMapClient:          coreClient,
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-key-dry-run", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-key-dry-run", recorder)
	if err := c.sync(ctx, syncCtx); err != nil {
		return fmt.Errorf("key controller dry-run failed: %w", err)
	}
	return nil
}

func dryRunStateController(
	ctx context.Context,
	overlay *dryRunSecretsGetter,
	instanceName string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	encryptionSecretSelector metav1.ListOptions,
) (*corev1.Secret, error) {
	dryRunOperatorClient, err := operatorClientForDryRun(operatorClient)
	if err != nil {
		return nil, err
	}

	c := &stateController{
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionState"),
		encryptionSecretSelector: encryptionSecretSelector,
		operatorClient:           dryRunOperatorClient,
		secretClient:             overlay,
		deployer:                 encryptionDeployer,
		provider:                 provider,
		preconditionsFulfilledFn: func() (bool, error) { return true, nil },
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-state-dry-run", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-state-dry-run", recorder)
	if err := c.sync(ctx, syncCtx); err != nil {
		return nil, fmt.Errorf("state controller dry-run failed: %w", err)
	}

	expectedName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, instanceName)
	ecSecret, ok := overlay.Recorded(openshiftConfigManagedNS, expectedName)
	if !ok {
		return nil, fmt.Errorf("state controller dry-run did not create or update encryption config secret %q", expectedName)
	}
	return ecSecret, nil
}

// operatorClientForDryRun snapshots the live operator spec/status into a fake client so Sync can
// read management state and unsupported config without writing degraded conditions to the cluster.
func operatorClientForDryRun(live operatorv1helpers.OperatorClient) (operatorv1helpers.OperatorClient, error) {
	spec, status, _, err := live.GetOperatorState()
	if err != nil {
		return nil, fmt.Errorf("failed to snapshot operator state for dry-run: %w", err)
	}
	var specCopy *operatorv1.OperatorSpec
	var statusCopy *operatorv1.OperatorStatus
	if spec != nil {
		specCopy = spec.DeepCopy()
	}
	if status != nil {
		statusCopy = status.DeepCopy()
	}
	return operatorv1helpers.NewFakeOperatorClient(specCopy, statusCopy, nil), nil
}

// rewritePreflightWriteKeyEndpoint rewrites the write-key KMS endpoint from the
// per-key production socket (kms-{id}.sock) to the fixed preflight socket
// (kms.sock). Today's preflight checker dials that fixed path, while the plugin
// builder uses each provider's Endpoint as -listen-address, so the dry-run
// secret must agree with the checker.
//
// TODO: once preflight dials the write-key socket (kms-{id}.sock) directly,
// this rewrite can be removed and the dry-run secret can be used as-is.
func rewritePreflightWriteKeyEndpoint(secret *corev1.Secret, keyID uint64) (*corev1.Secret, error) {
	cfg, err := encryptiondata.FromSecret(secret)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.Encryption == nil {
		return nil, fmt.Errorf("encryption configuration is empty")
	}

	// Provider names are "{keyID}_{resource}" (e.g. "2_secrets"). Match on name
	// rather than endpoint so we identify the write key by its stable identity.
	wantNamePrefix := fmt.Sprintf("%d_", keyID)
	rewrote := false
	for i := range cfg.Encryption.Resources {
		for j := range cfg.Encryption.Resources[i].Providers {
			kms := cfg.Encryption.Resources[i].Providers[j].KMS
			if kms == nil || !strings.HasPrefix(kms.Name, wantNamePrefix) {
				continue
			}
			kms.Endpoint = preflightKMSSocketEndpoint
			rewrote = true
		}
	}
	if !rewrote {
		return nil, fmt.Errorf("write-key KMS provider with name prefix %q not found in encryption config", wantNamePrefix)
	}

	return encryptiondata.ToSecret(secret.Namespace, secret.Name, cfg)
}
