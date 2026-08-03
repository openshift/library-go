package controllers

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

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
	preflightKMSSocketEndpoint = "unix:///var/run/kmsplugin/kms.sock"
	preflightTempNamespaceLabel = "encryption.apiserver.operator.openshift.io/kms-preflight"
)

// computeEncryptionConfigSecretInTempNamespace creates an ephemeral namespace, seeds it with
// existing encryption key secrets, runs the key and state controller cores against that
// namespace (without writing operator status), and returns the resulting encryption-config Secret.
// The temporary namespace is always deleted before returning.
//
// The live encryption deployer is treated as converged for this computation so preflight can
// proceed even when API server revisions have not converged. That matches in-place KMS field
// updates, which also apply without waiting for convergence; migration-triggering changes still
// only mint keys in the temp namespace (live keys are untouched).
func computeEncryptionConfigSecretInTempNamespace(
	ctx context.Context,
	configHash string,
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
) (secret *corev1.Secret, err error) {
	// Force converged so key/state sync can compute the desired encryption config.
	// When the live deployer is mid-rollout it returns (nil, false); wrapping keeps any
	// returned secret (usually nil when not converged) and allows the sync to proceed.
	effectiveDeployer := forceConvergedDeployer{delegate: encryptionDeployer}

	tempNamespace := preflightTempNamespaceName(configHash)
	if err := ensurePreflightTempNamespace(ctx, coreClient, tempNamespace); err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := deletePreflightTempNamespace(ctx, coreClient, tempNamespace); cleanupErr != nil {
			klog.Warningf("failed to delete preflight temp namespace %q: %v", tempNamespace, cleanupErr)
		}
	}()

	if err := seedEncryptionKeySecrets(ctx, coreClient, secrets.EncryptionKeysNamespace, tempNamespace, encryptionSecretSelector); err != nil {
		return nil, err
	}

	if err := runKeyControllerInNamespace(ctx, tempNamespace, instanceName, unsupportedConfigPrefix, provider, effectiveDeployer, operatorClient, apiServerClient, coreClient, encryptionSecretSelector); err != nil {
		return nil, err
	}

	encryptionSecret, err := runStateControllerInNamespace(ctx, tempNamespace, instanceName, provider, effectiveDeployer, operatorClient, coreClient, encryptionSecretSelector)
	if err != nil {
		return nil, err
	}

	keySecrets, err := secrets.ListKeySecretsInNamespace(ctx, coreClient, tempNamespace, encryptionSecretSelector)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("no encryption key secrets found after key controller run in temp namespace %q", tempNamespace)
	}

	rewritten, err := rewritePreflightWriteKeyEndpoint(encryptionSecret, latestKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to rewrite preflight KMS endpoint: %w", err)
	}
	return rewritten, nil
}

// forceConvergedDeployer reports converged=true while preserving the delegate's secret/error.
// Used by preflight so desired encryption-config computation is not blocked on revision rollout.
type forceConvergedDeployer struct {
	delegate statemachine.Deployer
}

func (d forceConvergedDeployer) DeployedEncryptionConfigSecret(ctx context.Context) (*corev1.Secret, bool, error) {
	secret, _, err := d.delegate.DeployedEncryptionConfigSecret(ctx)
	if err != nil {
		return nil, false, err
	}
	return secret, true, nil
}

func (d forceConvergedDeployer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return d.delegate.AddEventHandler(handler)
}

func (d forceConvergedDeployer) HasSynced() bool {
	return d.delegate.HasSynced()
}

func runKeyControllerInNamespace(
	ctx context.Context,
	keysNamespace string,
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
) error {
	c := &keyController{
		operatorClient:           operatorClient,
		apiServerClient:          apiServerClient,
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionKey"),
		unsupportedConfigPrefix:  unsupportedConfigPrefix,
		encryptionSecretSelector: encryptionSecretSelector,
		deployer:                 encryptionDeployer,
		provider:                 provider,
		preconditionsFulfilledFn: func() (bool, error) { return true, nil },
		secretClient:             coreClient,
		configMapClient:          coreClient,
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-key", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-key", recorder)
	if err := c.syncInternal(ctx, syncCtx, keySyncOptions{
		keysNamespace: keysNamespace,
		writeStatus:   false,
	}); err != nil {
		return fmt.Errorf("key controller temp-namespace run failed: %w", err)
	}
	return nil
}

func runStateControllerInNamespace(
	ctx context.Context,
	namespace string,
	instanceName string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	operatorClient operatorv1helpers.OperatorClient,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
) (*corev1.Secret, error) {
	c := &stateController{
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionState"),
		encryptionSecretSelector: encryptionSecretSelector,
		operatorClient:           operatorClient,
		secretClient:             coreClient,
		deployer:                 encryptionDeployer,
		provider:                 provider,
		preconditionsFulfilledFn: func() (bool, error) { return true, nil },
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-state", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-state", recorder)
	if err := c.syncInternal(ctx, syncCtx, stateSyncOptions{
		keysNamespace:             namespace,
		encryptionConfigNamespace: namespace,
		writeStatus:               false,
	}); err != nil {
		return nil, fmt.Errorf("state controller temp-namespace run failed: %w", err)
	}

	expectedName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, instanceName)
	ecSecret, err := coreClient.Secrets(namespace).Get(ctx, expectedName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("state controller did not create encryption config secret %s/%s: %w", namespace, expectedName, err)
	}
	return ecSecret, nil
}

func ensurePreflightTempNamespace(ctx context.Context, coreClient corev1client.CoreV1Interface, name string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				preflightTempNamespaceLabel: "true",
			},
		},
	}
	_, err := coreClient.Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create preflight temp namespace %q: %w", name, err)
	}
	return nil
}

func deletePreflightTempNamespace(ctx context.Context, coreClient corev1client.CoreV1Interface, name string) error {
	err := coreClient.Namespaces().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// seedEncryptionKeySecrets copies existing encryption key secrets from sourceNamespace into
// destNamespace so the key/state controllers can build on the live key set without mutating it.
func seedEncryptionKeySecrets(ctx context.Context, coreClient corev1client.CoreV1Interface, sourceNamespace, destNamespace string, encryptionSecretSelector metav1.ListOptions) error {
	existing, err := secrets.ListKeySecretsInNamespace(ctx, coreClient, sourceNamespace, encryptionSecretSelector)
	if err != nil {
		return fmt.Errorf("failed to list encryption key secrets in %s: %w", sourceNamespace, err)
	}
	for _, existingSecret := range existing {
		copySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        existingSecret.Name,
				Namespace:   destNamespace,
				Labels:      existingSecret.Labels,
				Annotations: existingSecret.Annotations,
				Finalizers:  existingSecret.Finalizers,
			},
			Type: existingSecret.Type,
			Data: existingSecret.Data,
		}
		_, err := coreClient.Secrets(destNamespace).Create(ctx, copySecret, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to seed encryption key secret %s/%s: %w", destNamespace, copySecret.Name, err)
		}
	}
	return nil
}

func preflightTempNamespaceName(configHash string) string {
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, configHash)
	sanitized = strings.Trim(sanitized, "-")
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}
	if sanitized == "" {
		sanitized = "unknown"
	}
	name := "kms-preflight-" + sanitized
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	return name
}

// rewritePreflightWriteKeyEndpoint rewrites the write-key KMS endpoint from the
// per-key production socket (kms-{id}.sock) to the fixed preflight socket
// (kms.sock). Today's preflight checker dials that fixed path, while the plugin
// builder uses each provider's Endpoint as -listen-address, so the secret must
// agree with the checker.
//
// TODO: once preflight dials the write-key socket (kms-{id}.sock) directly,
// this rewrite can be removed and the secret can be used as-is.
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
