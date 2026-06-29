package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"hash/fnv"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type kmsConfigHasher struct {
	provider   kmsProviderConfig
	coreClient corev1client.CoreV1Interface
	namespace  string
}

// newKMSConfigHasher creates a hasher for a KMS provider config and its referenced resources.
// namespace is the namespace where the referenced Secrets and ConfigMaps are stored (e.g., openshift-config).
func newKMSConfigHasher(provider kmsProviderConfig, coreClient corev1client.CoreV1Interface, namespace string) *kmsConfigHasher {
	return &kmsConfigHasher{provider: provider, coreClient: coreClient, namespace: namespace}
}

// hash computes a deterministic hash over the provider config and the specific data keys
// from its referenced Secret and ConfigMap. Uses FNV-32, JSON encoding, and base64 URL
// encoding, consistent with resourcehash.GetSecretHash and resourcehash.GetConfigMapHash.
func (h *kmsConfigHasher) hash(ctx context.Context) (string, error) {
	hasher := fnv.New32()

	if err := json.NewEncoder(hasher).Encode(h.provider.sourceConfig()); err != nil {
		return "", fmt.Errorf("failed to hash provider config: %w", err)
	}

	if err := h.hashReferencedSecret(ctx, hasher); err != nil {
		return "", err
	}
	if err := h.hashReferencedConfigMap(ctx, hasher); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

func (h *kmsConfigHasher) hashReferencedSecret(ctx context.Context, hasher hash.Hash) error {
	name, keys, err := h.provider.referencedSecretName()
	if err != nil {
		return fmt.Errorf("failed to get referenced secret name: %w", err)
	}
	if name == "" {
		return nil
	}

	secret, err := h.coreClient.Secrets(h.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %w", h.namespace, name, err)
	}

	// Write each key name before its value to prevent collisions when bytes
	// shift between adjacent values (e.g. role-id="ab",secret-id="cd" vs
	// role-id="abc",secret-id="d" would otherwise both hash as "abcd").
	sort.Strings(keys)
	for _, k := range keys {
		v, ok := secret.Data[k]
		if !ok {
			return fmt.Errorf("key %q not found in secret %s/%s", k, h.namespace, name)
		}
		if _, err := hasher.Write([]byte(k)); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
		if _, err := hasher.Write(v); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
	}
	return nil
}

func (h *kmsConfigHasher) hashReferencedConfigMap(ctx context.Context, hasher hash.Hash) error {
	name, keys, err := h.provider.referencedConfigMapName()
	if err != nil {
		return fmt.Errorf("failed to get referenced configmap name: %w", err)
	}
	if name == "" {
		return nil
	}

	cm, err := h.coreClient.ConfigMaps(h.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get configmap %s/%s: %w", h.namespace, name, err)
	}

	sort.Strings(keys)
	for _, k := range keys {
		v, ok := cm.Data[k]
		if !ok {
			return fmt.Errorf("key %q not found in configmap %s/%s", k, h.namespace, name)
		}
		if _, err := hasher.Write([]byte(k)); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
		if _, err := hasher.Write([]byte(v)); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
	}
	return nil
}

// KMSPreflightDeployer abstracts the lifecycle of a preflight workload that
// validates KMS plugin configuration before an encryption key is created.
// All methods are idempotent.
//
// Deploy creates all resources the workload needs (ServiceAccount, Secret,
// RBAC, Pod). The controller only calls Deploy when Status reports no pod
// exists, so no running pod can be affected.
//
// Cleanup removes all resources created by Deploy.
type KMSPreflightDeployer interface {
	// Deploy creates the preflight workload with the given config hash
	// and encryption configuration. It is idempotent.
	Deploy(ctx context.Context, configHash string, encryptionConfiguration *corev1.Secret) error

	// Status returns the current pod status of the preflight workload.
	// It returns an apierrors.IsNotFound error when no preflight pod exists.
	Status(ctx context.Context) (corev1.PodStatus, error)

	// Cleanup removes all resources created by Deploy.
	Cleanup(ctx context.Context) error
}

type kmsPreflightController struct {
	controllerInstanceName string

	operatorClient  operatorv1helpers.OperatorClient
	apiServerClient configv1client.APIServerInterface
	coreClient      corev1client.CoreV1Interface

	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
}

// NewKMSPreflightController validates KMS configuration before a key is created.
//
// Coordination with the key-controller:
//
// The key-controller writes a hash of the current KMS config to operator status
// as the EncryptionKMSPreflightRequired condition (hash in the message).
// This controller reads that hash, runs preflight checks, and on success sets
// the EncryptionKMSPreflightSucceeded condition (same hash in the message).
// The key-controller waits for the two hashes to match before creating a key.
//
// This is the same pattern used by the revision and installer controllers:
// the revision controller writes LatestAvailableRevision, the installer
// controller reads it and acts.
//
// Without this protocol the following race can occur:
//  1. Preflight passes for config A, hash A written to operator status.
//  2. Key-controller reads hash A, starts creating a key for config A.
//  3. Config changes to B.
//  4. Preflight controller syncs, sees config B, does not yet see the key
//     for A (key-controller is in the process of creating the key),
//     runs preflight for B, overwrites status with hash B.
//  5. The key created in step 2 was for config A but status now says B.
//
// Letting the key-controller own EncryptionKMSPreflightRequired and this
// controller own EncryptionKMSPreflightSucceeded solves this. If the config
// changes mid-flight the key-controller posts a new hash and the preflight
// controller sees the mismatch and waits.
//
// Example 1: config changes before key is created
//  1. User creates KMS config A.
//  2. Key-controller computes hash A, writes EncryptionKMSPreflightRequired=A.
//  3. Preflight controller sees required=A, starts checking A.
//  4. User changes config to A2 (minor variation, different hash).
//  5. Key-controller computes hash A2, writes EncryptionKMSPreflightRequired=A2.
//  6. Preflight controller sees required=A2, starts checking A2.
//  7. Key-controller does not create a key until succeeded=A2.
//
// Example 2: config changes after key is created
//  1. User creates KMS config A.
//  2. Key-controller computes hash A, writes EncryptionKMSPreflightRequired=A.
//  3. Preflight controller checks A, succeeds, writes EncryptionKMSPreflightSucceeded=A.
//  4. Key-controller sees required=A matches succeeded=A, creates key for A.
//  5. User changes config to A2 (or B).
//  6. Key-controller waits until the key for A completes the full cycle
//     (read, write, migrated) before creating a new key. No preflight done
//     at this stage.
//
// Preflight workload:
//
// A deployer interface abstracts the workload creation. Each operator provides
// its own implementation that knows how to install, get status, clean up the
// preflight workload, and wire the credentials needed to update pod status.
// The workload type matches the API server it validates (static pod for kas-o,
// Deployment for aggregated API servers).
//
// When an existing KMS plugin is already configured, the checker runs the new
// plugin alongside the existing one to catch co-existence issues (e.g., metric
// port collisions). When no plugin is configured yet, it runs the new plugin alone.
// The sync method reads existing encryption key secrets to determine whether
// a plugin is already configured.
//
// The pod uses readiness gates to post check results back to the controller.
// To set the readiness gate condition, the pod PATCHes its own status using
// credentials wired by the deployer.
// The controller reads these enhanced pod statuses to update its own operator
// status, which is propagated to end users.
//
// After a successful check the preflight pod is kept for a short period (e.g. 1h)
// so that its logs can be inspected, then cleaned up by a subsequent sync.
func NewKMSPreflightController(
	instanceName string,
	provider Provider,
	preconditionsFulfilledFn preconditionsFulfilled,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
	// coreClient reads referenced Secrets and ConfigMaps in openshift-config for hash
	// computation. No informer is needed: the key-controller detects config changes and
	// posts a new EncryptionKMSPreflightRequired condition, which triggers this controller
	// via the operatorClient informer. The minute-based resync covers the rest.
	coreClient corev1client.CoreV1Interface,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &kmsPreflightController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "EncryptionKMSPreflight"),

		operatorClient:  operatorClient,
		apiServerClient: apiServerClient,
		coreClient:      coreClient,

		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
	}

	return factory.New().
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		ResyncEvery(time.Minute).
		WithInformers(
			apiServerInformer.Informer(),
			operatorClient.Informer(),
		).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-kms-preflight-controller"),
	)
}

func (c *kmsPreflightController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	degradedCondition := applyoperatorv1.OperatorCondition().WithType("EncryptionKMSPreflightControllerDegraded")

	defer func() {
		if degradedCondition == nil {
			return
		}
		status := applyoperatorv1.OperatorStatus().WithConditions(degradedCondition)
		if applyError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); applyError != nil {
			err = applyError
		}
	}()

	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		if err != nil {
			degradedCondition = nil
		} else {
			degradedCondition = degradedCondition.WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	preflightErr := c.runPreflightChecks(ctx)
	if preflightErr != nil {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Error").
			WithMessage(preflightErr.Error())
	} else {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionFalse)
	}
	return preflightErr
}

func (c *kmsPreflightController) runPreflightChecks(ctx context.Context) error {
	requiredHash, err := c.requiredPreflightHash(ctx)
	if err != nil {
		return err
	}
	if requiredHash == "" {
		return nil
	}

	return fmt.Errorf("preflight checks not yet implemented for hash %s", requiredHash)
}

// requiredPreflightHash returns the config hash that needs preflight validation,
// or an empty string when no preflight is needed.
func (c *kmsPreflightController) requiredPreflightHash(ctx context.Context) (string, error) {
	_, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return "", fmt.Errorf("failed to get operator state: %w", err)
	}
	requiredCondition := operatorv1helpers.FindOperatorCondition(operatorStatus.Conditions, "EncryptionKMSPreflightRequired")
	if requiredCondition == nil || requiredCondition.Status != operatorv1.ConditionTrue {
		return "", nil
	}
	apiServer, err := c.apiServerClient.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get apiserver config: %w", err)
	}

	providerCfg, err := newKMSProviderConfig(apiServer.Spec.Encryption.KMS)
	if err != nil {
		return "", fmt.Errorf("failed to create KMS provider config: %w", err)
	}
	currentHash, err := newKMSConfigHasher(providerCfg, c.coreClient, openshiftConfigNS).hash(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to compute KMS config hash: %w", err)
	}

	requiredHash := requiredCondition.Message
	// No requeue needed: the key-controller will post an updated condition when it
	// picks up the config change (via apiServerInformer), which triggers us through
	// operatorClient.Informer(). The minute-based resync is a backstop.
	if currentHash != requiredHash {
		klog.V(4).Infof("KMS config hash changed: required=%s, current=%s; waiting for the key-controller to post an updated condition", requiredHash, currentHash)
		return "", nil
	}

	return requiredHash, nil
}
