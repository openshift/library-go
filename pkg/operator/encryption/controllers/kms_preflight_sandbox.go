package controllers

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing/fstest"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	"sigs.k8s.io/yaml"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/manifestclient"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
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

// staticEncryptionDeployer returns a fixed deployed encryption-config Secret as converged.
// Used so key/state dry-runs do not wait on operand revision convergence.
type staticEncryptionDeployer struct {
	secret *corev1.Secret
}

func (d *staticEncryptionDeployer) DeployedEncryptionConfigSecret(_ context.Context) (*corev1.Secret, bool, error) {
	return d.secret, true, nil
}

func (d *staticEncryptionDeployer) AddEventHandler(_ cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return nil, nil
}

func (d *staticEncryptionDeployer) HasSynced() bool {
	return true
}

// computeEncryptionConfigSecretDryRun runs KeyController.Sync then StateController.Sync against a
// manifestclient-backed sandbox seeded from the live cluster, then returns the encryption-config
// Secret those controllers would have applied — without writing key or encryption-config Secrets
// to the real API. Operator status updates from Sync are directed at a fake client snapshotted
// from the live operator state.
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
	liveDeployed, converged, err := encryptionDeployer.DeployedEncryptionConfigSecret(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get deployed encryption config: %w", err)
	}
	if !converged {
		return true, nil, nil
	}

	mapFS, err := seedPreflightSandboxFS(ctx, instanceName, apiServerClient, coreClient, encryptionSecretSelector, liveDeployed)
	if err != nil {
		return false, nil, err
	}

	keySecretName, err := dryRunKeyController(ctx, mapFS, instanceName, unsupportedConfigPrefix, provider, liveDeployed, operatorClient, apiServerClient, encryptionSecretSelector)
	if err != nil {
		return false, nil, err
	}

	encryptionSecret, err := dryRunStateController(ctx, mapFS, instanceName, provider, liveDeployed, operatorClient, encryptionSecretSelector)
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

func seedPreflightSandboxFS(
	ctx context.Context,
	instanceName string,
	apiServerClient configv1client.APIServerInterface,
	coreClient corev1client.CoreV1Interface,
	encryptionSecretSelector metav1.ListOptions,
	_ *corev1.Secret,
) (fstest.MapFS, error) {
	mapFS := fstest.MapFS{}

	keySecrets, err := secrets.ListKeySecrets(ctx, coreClient, encryptionSecretSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to list key secrets: %w", err)
	}
	for _, s := range keySecrets {
		if err := putSecretYAML(mapFS, s); err != nil {
			return nil, err
		}
	}

	managedEncryptionConfigName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, instanceName)
	managedEC, err := coreClient.Secrets(openshiftConfigManagedNS).Get(ctx, managedEncryptionConfigName, metav1.GetOptions{})
	switch {
	case err == nil:
		if err := putSecretYAML(mapFS, managedEC); err != nil {
			return nil, err
		}
	case apierrors.IsNotFound(err):
		// first encryption-config apply will Create
	default:
		return nil, fmt.Errorf("failed to get managed encryption config %s/%s: %w", openshiftConfigManagedNS, managedEncryptionConfigName, err)
	}

	apiServer, err := apiServerClient.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get apiserver config: %w", err)
	}
	if apiServer.Spec.Encryption.KMS.Type != "" {
		providerCfg, err := newKMSProviderConfig(apiServer.Spec.Encryption.KMS)
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS provider config: %w", err)
		}
		if err := seedReferencedKMSResources(ctx, mapFS, coreClient, providerCfg); err != nil {
			return nil, err
		}
	}

	return mapFS, nil
}

func seedReferencedKMSResources(ctx context.Context, mapFS fstest.MapFS, coreClient corev1client.CoreV1Interface, providerCfg kmsProviderConfig) error {
	secretName, _, err := providerCfg.referencedSecretName()
	if err != nil {
		return err
	}
	if secretName != "" {
		refSecret, err := coreClient.Secrets(openshiftConfigNS).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get referenced secret %s/%s: %w", openshiftConfigNS, secretName, err)
		}
		if err := putSecretYAML(mapFS, refSecret); err != nil {
			return err
		}
	}

	cmName, _, err := providerCfg.referencedConfigMapName()
	if err != nil {
		return err
	}
	if cmName != "" {
		refCM, err := coreClient.ConfigMaps(openshiftConfigNS).Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get referenced configmap %s/%s: %w", openshiftConfigNS, cmName, err)
		}
		if err := putConfigMapYAML(mapFS, refCM); err != nil {
			return err
		}
	}
	return nil
}

func dryRunKeyController(
	ctx context.Context,
	mapFS fstest.MapFS,
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	liveDeployed *corev1.Secret,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	encryptionSecretSelector metav1.ListOptions,
) (createdKeySecretName string, err error) {
	kube, trackingClient, err := newSandboxKubeClient(mapFS)
	if err != nil {
		return "", err
	}

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
		deployer:                 &staticEncryptionDeployer{secret: liveDeployed},
		provider:                 provider,
		preconditionsFulfilledFn: alwaysTruePreconditions,
		secretClient:             kube.CoreV1(),
		configMapClient:          kube.CoreV1(),
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-key-dry-run", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-key-dry-run", recorder)
	if err := c.Sync(ctx, syncCtx); err != nil {
		return "", fmt.Errorf("key controller dry-run failed: %w", err)
	}

	createdKeySecretName, body, err := findEncryptionKeyCreateMutation(trackingClient.GetMutations(), instanceName)
	if err != nil {
		return "", err
	}
	if err := putYAMLAtMustGatherPath(mapFS, openshiftConfigManagedNS, "secrets", createdKeySecretName, body); err != nil {
		return "", err
	}
	return createdKeySecretName, nil
}

func dryRunStateController(
	ctx context.Context,
	mapFS fstest.MapFS,
	instanceName string,
	provider Provider,
	liveDeployed *corev1.Secret,
	operatorClient operatorv1helpers.OperatorClient,
	encryptionSecretSelector metav1.ListOptions,
) (*corev1.Secret, error) {
	kube, trackingClient, err := newSandboxKubeClient(mapFS)
	if err != nil {
		return nil, err
	}

	dryRunOperatorClient, err := operatorClientForDryRun(operatorClient)
	if err != nil {
		return nil, err
	}

	c := &StateController{
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionState"),
		encryptionSecretSelector: encryptionSecretSelector,
		operatorClient:           dryRunOperatorClient,
		secretClient:             kube.CoreV1(),
		deployer:                 &staticEncryptionDeployer{secret: liveDeployed},
		provider:                 provider,
		preconditionsFulfilledFn: alwaysTruePreconditions,
	}

	recorder := events.NewInMemoryRecorder("kms-preflight-state-dry-run", clock.RealClock{})
	syncCtx := factory.NewSyncContext("kms-preflight-state-dry-run", recorder)
	if err := c.Sync(ctx, syncCtx); err != nil {
		return nil, fmt.Errorf("state controller dry-run failed: %w", err)
	}

	expectedName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, instanceName)
	return findEncryptionConfigMutation(trackingClient.GetMutations(), expectedName)
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

func newSandboxKubeClient(mapFS fstest.MapFS) (kubernetes.Interface, manifestclient.MutationTrackingClient, error) {
	trackingClient := manifestclient.NewTestingHTTPClient(mapFS)
	kube, err := manifestclient.RecommendedKubernetesWithClient(trackingClient.GetHTTPClient())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build sandbox kubernetes client: %w", err)
	}
	return kube, trackingClient, nil
}

func findEncryptionKeyCreateMutation(mutations *manifestclient.AllActionsTracker[manifestclient.TrackedSerializedRequest], instanceName string) (name string, body []byte, err error) {
	prefix := encryptionKeySecretNamePrefix + instanceName + "-"
	for _, req := range mutations.AllRequests() {
		sr := req.GetSerializedRequest()
		if sr.Action != manifestclient.ActionCreate {
			continue
		}
		if sr.ResourceType.Resource != "secrets" || sr.Namespace != openshiftConfigManagedNS {
			continue
		}
		if !strings.HasPrefix(sr.Name, prefix) {
			continue
		}
		return sr.Name, append([]byte(nil), sr.Body...), nil
	}
	return "", nil, fmt.Errorf("preflight required but key controller dry-run did not create a new encryption key secret")
}

func findEncryptionConfigMutation(mutations *manifestclient.AllActionsTracker[manifestclient.TrackedSerializedRequest], expectedName string) (*corev1.Secret, error) {
	for _, req := range mutations.AllRequests() {
		sr := req.GetSerializedRequest()
		switch sr.Action {
		case manifestclient.ActionCreate, manifestclient.ActionUpdate:
		default:
			continue
		}
		if sr.ResourceType.Resource != "secrets" || sr.Namespace != openshiftConfigManagedNS || sr.Name != expectedName {
			continue
		}
		secret := &corev1.Secret{}
		if err := yaml.Unmarshal(sr.Body, secret); err != nil {
			return nil, fmt.Errorf("failed to decode encryption config mutation body: %w", err)
		}
		secret.APIVersion = "v1"
		secret.Kind = "Secret"
		return secret, nil
	}
	return nil, fmt.Errorf("state controller dry-run did not create or update encryption config secret %q", expectedName)
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

func putSecretYAML(mapFS fstest.MapFS, secret *corev1.Secret) error {
	copy := secret.DeepCopy()
	copy.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}
	copy.ManagedFields = nil
	body, err := yaml.Marshal(copy)
	if err != nil {
		return fmt.Errorf("failed to marshal secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	return putYAMLAtMustGatherPath(mapFS, secret.Namespace, "secrets", secret.Name, body)
}

func putConfigMapYAML(mapFS fstest.MapFS, cm *corev1.ConfigMap) error {
	copy := cm.DeepCopy()
	copy.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}
	copy.ManagedFields = nil
	body, err := yaml.Marshal(copy)
	if err != nil {
		return fmt.Errorf("failed to marshal configmap %s/%s: %w", cm.Namespace, cm.Name, err)
	}
	return putYAMLAtMustGatherPath(mapFS, cm.Namespace, "configmaps", cm.Name, body)
}

func putYAMLAtMustGatherPath(mapFS fstest.MapFS, namespace, resource, name string, body []byte) error {
	path := filepath.Join("namespaces", namespace, "core", resource, name+".yaml")
	mapFS[path] = &fstest.MapFile{Data: body}
	return nil
}
