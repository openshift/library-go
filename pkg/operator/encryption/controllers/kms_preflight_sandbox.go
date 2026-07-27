package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/clock"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	openshiftConfigManagedNS      = "openshift-config-managed"
	preflightKMSSocketEndpoint    = "unix:///var/run/kmsplugin/kms.sock"
	encryptionKeySecretNamePrefix = "encryption-key-"
)

// computeEncryptionConfigSecretDryRun runs KeyController.Sync then StateController.Sync against the
// live cluster but intercepts their writes, returning the encryption-config Secret those controllers
// would have applied without persisting the key or encryption-config Secrets to the real API.
// If the live encryption deployer reports !converged, requeue is true.
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

	// interceptor is shared between both dry-run runs so the key secret created by
	// KeyController is visible to StateController's List call.
	keySecretPrefix := encryptionKeySecretNamePrefix + instanceName + "-"
	ecSecretName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, instanceName)
	interceptor := newInterceptingSecretsGetter(coreClient, func(namespace, name string) bool {
		return namespace == openshiftConfigManagedNS &&
			(strings.HasPrefix(name, keySecretPrefix) || name == ecSecretName)
	})

	keySecretName, err := dryRunKeyController(ctx, interceptor, instanceName, unsupportedConfigPrefix, provider, encryptionDeployer, operatorClient, apiServerClient, coreClient, encryptionSecretSelector)
	if err != nil {
		return false, nil, err
	}

	encryptionSecret, err := dryRunStateController(ctx, interceptor, instanceName, provider, encryptionDeployer, operatorClient, encryptionSecretSelector)
	if err != nil {
		return false, nil, err
	}

	keyID, ok := state.NameToKeyID(keySecretName)
	if !ok {
		return false, nil, fmt.Errorf("unable to parse key ID from dry-run key secret %q", keySecretName)
	}

	rewritten, err := rewritePreflightWriteKeyEndpoint(encryptionSecret, keyID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to rewrite preflight KMS endpoint: %w", err)
	}
	return false, rewritten, nil
}

func dryRunKeyController(
	ctx context.Context,
	interceptor *interceptingSecretsGetter,
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
) (createdKeySecretName string, err error) {
	dryRunOperatorClient, err := operatorClientForDryRun(operatorClient)
	if err != nil {
		return "", err
	}

	c := &KeyController{
		operatorClient:           dryRunOperatorClient,
		apiServerClient:          apiServerClient,
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionKey"),
		unsupportedConfigPrefix:  unsupportedConfigPrefix,
		encryptionSecretSelector: encryptionSecretSelector,
		deployer:                 encryptionDeployer,
		provider:                 provider,
		preconditionsFulfilledFn: alwaysTruePreconditions,
		secretClient:             interceptor,
		configMapClient:          coreClient,
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-key-dry-run", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-key-dry-run", recorder)
	if err := c.Sync(ctx, syncCtx); err != nil {
		return "", fmt.Errorf("key controller dry-run failed: %w", err)
	}

	prefix := encryptionKeySecretNamePrefix + instanceName + "-"
	created, err := interceptor.findWritten(func(s *corev1.Secret) bool {
		return s.Namespace == openshiftConfigManagedNS && strings.HasPrefix(s.Name, prefix)
	})
	if err != nil {
		return "", fmt.Errorf("preflight required but key controller dry-run did not create a new encryption key secret")
	}
	return created.Name, nil
}

func dryRunStateController(
	ctx context.Context,
	interceptor *interceptingSecretsGetter,
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

	c := &StateController{
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionState"),
		encryptionSecretSelector: encryptionSecretSelector,
		operatorClient:           dryRunOperatorClient,
		secretClient:             interceptor,
		deployer:                 encryptionDeployer,
		provider:                 provider,
		preconditionsFulfilledFn: alwaysTruePreconditions,
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-state-dry-run", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-state-dry-run", recorder)
	if err := c.Sync(ctx, syncCtx); err != nil {
		return nil, fmt.Errorf("state controller dry-run failed: %w", err)
	}

	expectedName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, instanceName)
	ecSecret, err := interceptor.findWritten(func(s *corev1.Secret) bool {
		return s.Namespace == openshiftConfigManagedNS && s.Name == expectedName
	})
	if err != nil {
		return nil, fmt.Errorf("state controller dry-run did not create or update encryption config secret %q", expectedName)
	}
	return ecSecret, nil
}

func alwaysTruePreconditions() (bool, error) {
	return true, nil
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

func rewritePreflightWriteKeyEndpoint(secret *corev1.Secret, keyID uint64) (*corev1.Secret, error) {
	cfg, err := encryptiondata.FromSecret(secret)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.Encryption == nil {
		return nil, fmt.Errorf("encryption configuration is empty")
	}

	wantOld := fmt.Sprintf("unix:///var/run/kmsplugin/kms-%d.sock", keyID)
	keyIDStr := strconv.FormatUint(keyID, 10)
	rewrote := false
	for i := range cfg.Encryption.Resources {
		for j := range cfg.Encryption.Resources[i].Providers {
			kms := cfg.Encryption.Resources[i].Providers[j].KMS
			if kms == nil {
				continue
			}
			if kms.Endpoint == wantOld || kms.Name == keyIDStr || strings.HasPrefix(kms.Name, keyIDStr+"_") {
				kms.Endpoint = preflightKMSSocketEndpoint
				rewrote = true
			}
		}
	}
	if !rewrote {
		// If we cannot identify the write key precisely, point the first KMS provider at the
		// preflight socket so the checker can dial it.
		for i := range cfg.Encryption.Resources {
			for j := range cfg.Encryption.Resources[i].Providers {
				if cfg.Encryption.Resources[i].Providers[j].KMS != nil {
					cfg.Encryption.Resources[i].Providers[j].KMS.Endpoint = preflightKMSSocketEndpoint
					rewrote = true
					break
				}
			}
			if rewrote {
				break
			}
		}
	}

	return encryptiondata.ToSecret(secret.Namespace, secret.Name, cfg)
}
