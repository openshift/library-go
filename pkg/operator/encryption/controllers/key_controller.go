package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/crypto"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// encryptionSecretMigrationInterval determines how much time must pass after a key has been observed as
// migrated before a new key is created by the key minting controller.  The new key's ID will be one
// greater than the last key's ID (the first key has a key ID of 1).
const (
	encryptionSecretMigrationInterval = time.Hour * 24 * 7 // one week
	kmsEndpointFormat                 = "unix:///var/run/kmsplugin/kms-%d.sock"
	defaultKMSTimeout                 = 10 * time.Second
	openshiftConfigNS                 = "openshift-config"
)

// keyController creates new keys if necessary. It
// * watches
//   - secrets in openshift-config-managed
//   - pods in target namespace
//   - secrets in target namespace
//   - computes a new, desired encryption config from encryption-config-<revision>
//     and the existing keys in openshift-config-managed.
//   - derives from the desired encryption config whether a new key is needed due to
//   - encryption is being enabled via the API or
//   - a new to-be-encrypted resource shows up or
//   - the EncryptionType in the API does not match with the newest existing key or
//   - based on time (once a week is the proposed rotation interval) or
//   - an external reason given as a string in .encryption.reason of UnsupportedConfigOverrides.
//     It then creates it.
//
// Note: the "based on time" reason for a new key is based on the annotation
//
//	encryption.apiserver.operator.openshift.io/migrated-timestamp instead of
//	the key secret's creationTimestamp because the clock is supposed to
//	start when a migration has been finished, not when it begins.
type keyController struct {
	operatorClient  operatorv1helpers.OperatorClient
	apiServerClient configv1client.APIServerInterface

	controllerInstanceName   string
	instanceName             string
	encryptionSecretSelector metav1.ListOptions

	deployer                 statemachine.Deployer
	secretClient             corev1client.SecretsGetter
	configMapClient          corev1client.ConfigMapsGetter
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled

	// encryptionStatusProvider gates KMS key creation on a preflight check.
	encryptionStatusProvider kms.EncryptionStatusProvider

	unsupportedConfigPrefix []string
}

func NewKeyController(
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	deployer statemachine.Deployer,
	preconditionsFulfilledFn preconditionsFulfilled,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	configMapClient corev1client.ConfigMapsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
	// encryptionStatusProvider is required for KMS operators; it gates key creation on a preflight check.
	encryptionStatusProvider kms.EncryptionStatusProvider,
) factory.Controller {
	c := &keyController{
		operatorClient:  operatorClient,
		apiServerClient: apiServerClient,

		instanceName:            instanceName,
		controllerInstanceName:  factory.ControllerInstanceName(instanceName, "EncryptionKey"),
		unsupportedConfigPrefix: unsupportedConfigPrefix,

		encryptionSecretSelector: encryptionSecretSelector,
		deployer:                 deployer,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
		secretClient:             secretClient,
		configMapClient:          configMapClient,

		encryptionStatusProvider: encryptionStatusProvider,
	}

	return factory.New().
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		// Keep the resync interval short: openshift-config secrets/configmaps are not
		// watched directly, so credential and CA bundle rotations are only detected on
		// resync. Increasing this significantly delays in-place config propagation.
		ResyncEvery(time.Minute).
		WithInformers(
			apiServerInformer.Informer(),
			operatorClient.Informer(),
			kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
			// openshift-config secrets/configmaps are not watched directly. While we could
			// build a mechanism to watch only the referenced resources, creating and
			// maintaining it is not free, and watching all resources in the namespace
			// would create excessive API server load. Instead, changes are picked up
			// on the next periodic resync.
			deployer,
		).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-key-controller"),
	)
}

func (c *keyController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	// The status for this condition is intentionally omitted to ensure it's correctly set in each branch
	degradedCondition := applyoperatorv1.OperatorCondition().
		WithType("EncryptionKeyControllerDegraded")

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
			degradedCondition = degradedCondition.
				WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	err = c.checkAndCreateKeys(ctx, syncCtx, c.provider.EncryptedGRs())
	if err != nil {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Error").
			WithMessage(err.Error())
	} else {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionFalse)
	}

	return err
}

func (c *keyController) checkAndCreateKeys(ctx context.Context, syncContext factory.SyncContext, encryptedGRs []schema.GroupResource) error {
	planner := NewEncryptionPlanner(c.instanceName, c.unsupportedConfigPrefix, c.deployer, c.secretClient, c.configMapClient, c.apiServerClient, c.operatorClient, c.encryptionSecretSelector)
	snap, err := planner.Load(ctx, encryptedGRs, LoadOptions{})
	if err != nil {
		return err
	}
	if len(snap.State.ProgressingReason) > 0 {
		syncContext.Queue().AddAfter(syncContext.QueueKey(), 2*time.Minute)
		return nil
	}

	plan, err := planner.PlanNextKey(snap)
	if err != nil {
		return err
	}
	if !plan.Needed {
		return nil
	}

	keySecret, preconditionMet, err := c.generateKeySecret(ctx, plan.KeyID, snap.CurrentMode, snap.APIEncryption, snap.desiredProviderCfg, plan.InternalReason, snap.ExternalReason)
	if err != nil {
		return fmt.Errorf("failed to create key: %v", err)
	}
	if !preconditionMet {
		syncContext.Queue().AddAfter(syncContext.QueueKey(), 30*time.Second)
		return nil
	}

	_, createErr := c.secretClient.Secrets("openshift-config-managed").Create(ctx, keySecret, metav1.CreateOptions{})
	if errors.IsAlreadyExists(createErr) {
		return c.validateExistingSecret(ctx, keySecret, plan.KeyID)
	}
	if createErr != nil {
		syncContext.Recorder().Warningf("EncryptionKeyCreateFailed", "Secret %q failed to create: %v", keySecret.Name, createErr)
		return createErr
	}

	syncContext.Recorder().Eventf("EncryptionKeyCreated", "Secret %q successfully created: %q", keySecret.Name, plan.Reasons)

	return nil
}

func (c *keyController) validateExistingSecret(ctx context.Context, keySecret *corev1.Secret, keyID uint64) error {
	actualKeySecret, err := c.secretClient.Secrets("openshift-config-managed").Get(ctx, keySecret.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	actualKeyID, ok := state.NameToKeyID(actualKeySecret.Name)
	if !ok || actualKeyID != keyID {
		// TODO we can just get stuck in degraded here ...
		return fmt.Errorf("secret %s has an invalid name, new keys cannot be created for encryption target", keySecret.Name)
	}

	if _, err := secrets.ToKeyState(actualKeySecret); err != nil {
		return fmt.Errorf("secret %s is invalid, new keys cannot be created for encryption target", keySecret.Name)
	}

	return nil // we made this key earlier
}

// generateKeySecret builds the key secret for the given key ID and mode.
//
// For KMS mode it also computes the config hash (from the referenced Secret and
// ConfigMap buildEncryptionKeyState already reads) and gates on the KMS preflight check.
// The boolean return value signals the outcome:
//
//   - (secret, true,  nil) — preflight passed; caller should persist the key.
//   - (nil,   false, nil) — preflight still in progress; caller should back off.
//   - (nil,   false, err) — preflight failed or transient error; caller should surface it.
func (c *keyController) generateKeySecret(ctx context.Context, keyID uint64, currentMode state.Mode, apiServerEncryption configv1.APIServerEncryption, desiredProviderCfg kmsProviderConfig, internalReason, externalReason string) (*corev1.Secret, bool, error) {
	ks, refSecret, refCM, err := buildEncryptionKeyState(ctx, keyID, currentMode, apiServerEncryption, desiredProviderCfg, c.secretClient, c.configMapClient, internalReason, externalReason)
	if err != nil {
		return nil, false, err
	}
	if currentMode == state.KMS {
		resources := &prefetchedKMSConfigHasherResourceProvider{secret: refSecret, configMap: refCM}
		hasher, err := newKMSConfigHasher(desiredProviderCfg, resources, openshiftConfigNS)
		if err != nil {
			return nil, false, fmt.Errorf("failed to create KMS config hasher: %w", err)
		}
		configHash, err := hasher.hash(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("failed to compute KMS config hash: %w", err)
		}
		preflightPassed, err := c.ensureKMSPreflightPassed(ctx, configHash)
		if err != nil {
			return nil, false, err
		}
		if !preflightPassed {
			return nil, false, nil
		}
	}
	secret, err := secrets.FromKeyState(c.instanceName, ks)
	if err != nil {
		return nil, false, err
	}
	return secret, true, nil
}

func buildEncryptionKeyState(ctx context.Context, keyID uint64, currentMode state.Mode, apiServerEncryption configv1.APIServerEncryption, desiredProviderCfg kmsProviderConfig, secretClient corev1client.SecretsGetter, configMapClient corev1client.ConfigMapsGetter, internalReason string, externalReason string) (state.KeyState, *corev1.Secret, *corev1.ConfigMap, error) {
	bs := crypto.ModeToNewKeyFunc[currentMode]()
	ks := state.KeyState{
		Key: apiserverv1.Key{
			Name:   fmt.Sprintf("%d", keyID),
			Secret: base64.StdEncoding.EncodeToString(bs),
		},
		Mode:           currentMode,
		InternalReason: internalReason,
		ExternalReason: externalReason,
	}

	if currentMode != state.KMS {
		return ks, nil, nil, nil
	}

	ks.KMS = &state.KMSState{
		Encryption: &apiserverv1.KMSConfiguration{
			APIVersion: "v2",
			Name:       fmt.Sprintf("%d", keyID),
			Endpoint:   fmt.Sprintf(kmsEndpointFormat, keyID),
			Timeout:    &metav1.Duration{Duration: defaultKMSTimeout},
		},
		Plugin: apiServerEncryption.KMS,
	}

	refSecret, refCM, err := fetchReferencedResources(ctx, desiredProviderCfg, secretClient, configMapClient, openshiftConfigNS)
	if err != nil {
		return state.KeyState{}, nil, nil, err
	}
	if refSecret != nil {
		secretName, expectedKeys, err := desiredProviderCfg.referencedSecretName()
		if err != nil {
			return state.KeyState{}, nil, nil, err
		}
		for _, key := range expectedKeys {
			if err := ks.KMS.PluginSecretData.Set(secretName, key, refSecret.Data[key]); err != nil {
				return state.KeyState{}, nil, nil, err
			}
		}
	}
	if refCM != nil {
		cmName, expectedKeys, err := desiredProviderCfg.referencedConfigMapName()
		if err != nil {
			return state.KeyState{}, nil, nil, err
		}
		for _, key := range expectedKeys {
			if err := ks.KMS.PluginConfigMapData.Set(cmName, key, []byte(refCM.Data[key])); err != nil {
				return state.KeyState{}, nil, nil, err
			}
		}
	}

	return ks, refSecret, refCM, nil
}

// fetchReferencedResources loads the Secret and ConfigMap referenced by providerCfg from namespace, validating that every expected key is present. Either return value may be nil when the provider does not reference that resource type.
func fetchReferencedResources(ctx context.Context, providerCfg kmsProviderConfig, secretClient corev1client.SecretsGetter, configMapClient corev1client.ConfigMapsGetter, namespace string) (*corev1.Secret, *corev1.ConfigMap, error) {
	var refSecret *corev1.Secret
	if secretName, expectedKeys, err := providerCfg.referencedSecretName(); err != nil {
		return nil, nil, err
	} else if len(secretName) > 0 {
		refSecret, err = secretClient.Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get secret %s in %s: %w", secretName, namespace, err)
		}
		for _, key := range expectedKeys {
			if _, ok := refSecret.Data[key]; !ok {
				return nil, nil, fmt.Errorf("secret %s in %s is missing required key %q", secretName, namespace, key)
			}
		}
	}

	var refCM *corev1.ConfigMap
	if cmName, expectedKeys, err := providerCfg.referencedConfigMapName(); err != nil {
		return nil, nil, err
	} else if len(cmName) > 0 {
		refCM, err = configMapClient.ConfigMaps(namespace).Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get configmap %s in %s: %w", cmName, namespace, err)
		}
		for _, key := range expectedKeys {
			if _, ok := refCM.Data[key]; !ok {
				return nil, nil, fmt.Errorf("configmap %s in %s is missing required key %q", cmName, namespace, key)
			}
		}
	}

	return refSecret, refCM, nil
}

func modeAndExternalReasonFromAPIServerEncryption(encryption configv1.APIServerEncryption, operatorClient operatorv1helpers.OperatorClient, unsupportedConfigPrefix []string) (state.Mode, string, configv1.APIServerEncryption, error) {
	operatorSpec, _, _, err := operatorClient.GetOperatorState()
	if err != nil {
		return "", "", configv1.APIServerEncryption{}, err
	}

	encryptionConfig, err := structuredUnsupportedConfigFrom(operatorSpec.UnsupportedConfigOverrides.Raw, unsupportedConfigPrefix)
	if err != nil {
		return "", "", configv1.APIServerEncryption{}, err
	}

	reason := encryptionConfig.Encryption.Reason
	switch currentMode := state.Mode(encryption.Type); currentMode {
	case state.AESCBC, state.AESGCM, state.Identity: // secretbox is disabled for now
		return currentMode, reason, encryption, nil
	case state.KMS:
		return currentMode, reason, encryption, nil
	case "": // unspecified means use the default (which can change over time)
		return state.DefaultMode, reason, encryption, nil
	default:
		return "", "", configv1.APIServerEncryption{}, fmt.Errorf("unknown encryption mode configured: %s", currentMode)
	}
}

// modeAndExternalReasonFromAPIServer returns the active encryption mode, any external rotation
// reason from unsupported config overrides, and the cluster APIServer encryption spec.
func modeAndExternalReasonFromAPIServer(ctx context.Context, apiServerClient configv1client.APIServerInterface, operatorClient operatorv1helpers.OperatorClient, unsupportedConfigPrefix []string) (state.Mode, string, configv1.APIServerEncryption, error) {
	apiServer, err := apiServerClient.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return "", "", configv1.APIServerEncryption{}, err
	}

	return modeAndExternalReasonFromAPIServerEncryption(apiServer.Spec.Encryption, operatorClient, unsupportedConfigPrefix)
}

var _ kmsConfigHasherResourceProvider = &prefetchedKMSConfigHasherResourceProvider{}

// prefetchedKMSConfigHasherResourceProvider implements kmsConfigHasherResourceProvider using Secret and
// ConfigMap objects already fetched by the key controller while building the key
// secret, avoiding a second API round-trip for hash computation.
type prefetchedKMSConfigHasherResourceProvider struct {
	secret    *corev1.Secret
	configMap *corev1.ConfigMap
}

func (p *prefetchedKMSConfigHasherResourceProvider) getSecret(_ context.Context, namespace, name string) (*corev1.Secret, error) {
	if p.secret == nil || p.secret.Namespace != namespace || p.secret.Name != name {
		return nil, fmt.Errorf("prefetched secret does not match requested %s/%s", namespace, name)
	}
	return p.secret, nil
}

func (p *prefetchedKMSConfigHasherResourceProvider) getConfigMap(_ context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	if p.configMap == nil || p.configMap.Namespace != namespace || p.configMap.Name != name {
		return nil, fmt.Errorf("prefetched configmap does not match requested %s/%s", namespace, name)
	}
	return p.configMap, nil
}

// ensureKMSPreflightPassed checks whether the KMS preflight has passed for the
// given config hash. It writes ObservedConfigHash when not yet set (which triggers
// the preflight controller to run the check), then inspects the Result.
//
// Scenarios:
//
//  1. ObservedConfigHash does not match configHash — write it and back off.
//     The preflight controller will pick up the new hash and start the check.
//
//  2. ObservedConfigHash matches, Result.Status is Succeeded — proceed.
//
//  3. ObservedConfigHash matches, Result.Status is Failed — surface the error.
//     The admin must fix the KMS configuration (which produces a new hash)
//     before the key controller can proceed.
//
//  4. ObservedConfigHash matches, no result yet — preflight still in progress,
//     back off.
//
// Callers are responsible for requeuing when this returns (false, nil).
func (c *keyController) ensureKMSPreflightPassed(ctx context.Context, configHash string) (bool, error) {
	encryptionStatus, err := c.encryptionStatusProvider.GetKMSEncryptionStatus(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get KMS encryption status: %w", err)
	}

	// Scenario 1: ObservedConfigHash outdated — schedule the preflight check.
	if encryptionStatus.Preflight.ObservedConfigHash != configHash {
		if err := c.encryptionStatusProvider.UpdateKMSEncryptionStatus(ctx, func(s *operatorv1.KMSEncryptionStatus) {
			s.Preflight.ObservedConfigHash = configHash
		}); err != nil {
			return false, fmt.Errorf("failed to write preflight observed config hash: %w", err)
		}
		// Scenario 1: back off: wait for the preflight controller to pick up the new hash.
		return false, nil
	}

	// Scenario 2: preflight passed — proceed.
	if isPreflightResultSucceeded(&encryptionStatus.Preflight.Result, configHash) {
		return true, nil
	}
	// Scenario 3: preflight failed — surface the error.
	if isPreflightResultFailed(&encryptionStatus.Preflight.Result, configHash) {
		return false, fmt.Errorf("KMS preflight check failed for config hash %s; fix the KMS configuration to proceed", configHash)
	}
	// Scenario 4: back off: preflight check is still in progress.
	return false, nil
}

type encryptionKeyPlan struct {
	needed         bool
	keyID          uint64
	reasons        []string
	internalReason string
}

func planNextEncryptionKey(desiredEncryptionState map[schema.GroupResource]state.GroupResourceState, currentMode state.Mode, externalReason string, encryptedGRs []schema.GroupResource, desiredProviderCfg kmsProviderConfig) (*encryptionKeyPlan, error) {
	plan := &encryptionKeyPlan{}
	reasons := []string{}

	var (
		commonReason        string
		hasCommonReason     bool
		commonReasonDiffers bool
	)

	for gr, grKeys := range desiredEncryptionState {
		latestKeyID, internalReason, needed, err := needsNewKey(grKeys, currentMode, externalReason, encryptedGRs, desiredProviderCfg)
		if err != nil {
			return nil, err
		}
		if !needed {
			continue
		}

		if !hasCommonReason {
			commonReason = internalReason
			hasCommonReason = true
		} else if commonReason != internalReason {
			commonReasonDiffers = true
		}

		plan.needed = true
		nextKeyID := latestKeyID + 1
		if plan.keyID < nextKeyID {
			plan.keyID = nextKeyID
		}
		reasons = append(reasons, fmt.Sprintf("%s-%s", gr.Resource, internalReason))
	}

	if !plan.needed {
		return plan, nil
	}
	if hasCommonReason && !commonReasonDiffers && len(reasons) > 1 {
		reasons = []string{commonReason}
	}

	sort.Strings(reasons)
	plan.reasons = reasons
	plan.internalReason = strings.Join(reasons, ", ")
	return plan, nil
}

// needsNewKey checks whether a new key must be created for the given resource. If true, it also returns the latest
// used key ID and a reason string.
func needsNewKey(grKeys state.GroupResourceState, currentMode state.Mode, externalReason string, encryptedGRs []schema.GroupResource, desiredProviderCfg kmsProviderConfig) (uint64, string, bool, error) {
	// we always need to have some encryption keys unless we are turned off
	if len(grKeys.ReadKeys) == 0 {
		return 0, "key-does-not-exist", currentMode != state.Identity, nil
	}

	latestKey := grKeys.ReadKeys[0]
	latestKeyID, ok := state.NameToKeyID(latestKey.Key.Name)
	if !ok {
		return latestKeyID, fmt.Sprintf("key-secret-%d-is-invalid", latestKeyID), true, nil
	}

	// if latest secret has been deleted, we will never be able to migrate to that key.
	if !latestKey.Backed {
		return latestKeyID, fmt.Sprintf("encryption-config-key-%d-not-backed-by-secret", latestKeyID), true, nil
	}

	// check that we have pruned read-keys: the write-keys, plus at most one more backed read-key (potentially some unbacked once before)
	backedKeys := 0
	for _, rk := range grKeys.ReadKeys {
		if rk.Backed {
			backedKeys++
		}
	}
	if backedKeys > 2 {
		return 0, "", false, nil
	}

	// we have not migrated the latest key, do nothing until that is complete
	if allMigrated, _, _ := state.MigratedFor(encryptedGRs, latestKey); !allMigrated {
		return 0, "", false, nil
	}

	// if the most recent secret was encrypted in a mode different than the current mode, we need to generate a new key
	if latestKey.Mode != currentMode {
		return latestKeyID, "encryption-mode-changed", true, nil
	}

	// if the most recent secret turned off encryption and we want to keep it that way, do nothing
	if latestKey.Mode == state.Identity && currentMode == state.Identity {
		return 0, "", false, nil
	}

	if currentMode == state.KMS {
		// We are here because Encryption Mode is not changed
		// However, we need to create a new key if migration-triggering fields
		// in the KMS provider configuration have changed.
		if latestKey.KMS == nil {
			return 0, "", false, fmt.Errorf("KMS-mode key %q has nil KMS state, possibly corrupted key secret", latestKey.Key.Name)
		}
		same, err := desiredProviderCfg.sameProviderInstance(latestKey.KMS.Plugin)
		if err != nil {
			return 0, "", false, fmt.Errorf("failed to check KMS provider instance: %w", err)
		}
		if !same {
			return latestKeyID, "kms-provider-changed", true, nil
		}

		// For KMS mode, we don't do time-based rotation. KMS keys are rotated
		// externally by the KMS provider. Moreover, we don't trigger new key when external reason is changed.
		// Because it would lead to duplicate providers which is not allowed.
		return 0, "", false, nil
	}

	// if the most recent secret has a different external reason than the current reason, we need to generate a new key
	if latestKey.ExternalReason != externalReason && len(externalReason) != 0 {
		return latestKeyID, "external-reason-changed", true, nil
	}

	// we check for encryptionSecretMigratedTimestamp set by migration controller to determine when migration completed
	// this also generates back pressure for key rotation when migration takes a long time or was recently completed
	return latestKeyID, "rotation-interval-has-passed", time.Since(latestKey.Migrated.Timestamp) > encryptionSecretMigrationInterval, nil
}

// kmsProviderConfig abstracts provider-specific KMS logic so that every
// provider-type switch lives in a single factory (newKMSProviderConfig).
type kmsProviderConfig interface {
	// sourceConfig returns the provider-specific API configuration.
	sourceConfig() interface{}
	// referencedSecretName returns the name of the secret referenced by the KMS plugin
	// config and the specific data keys to carry from that secret. Only the listed keys
	// are copied into the Key Secret; any other data in the referenced secret is ignored.
	referencedSecretName() (string, []string, error)
	// referencedConfigMapName returns the name of the configmap referenced by the KMS plugin
	// config and the specific data keys to carry from that configmap. Only the listed keys
	// are copied into the Key Secret; any other data in the referenced configmap is ignored.
	referencedConfigMapName() (string, []string, error)
	// sameProviderInstance reports whether latest (stored in the key secret)
	// and this provider config refer to the same KMS provider instance.
	// Returns false when migration-triggering fields differ (e.g. VaultAddress, VaultKeyPath).
	sameProviderInstance(stored configv1.KMSPluginConfig) (bool, error)
}

// noopKMSProviderConfig is a safe zero-value implementation used for non-KMS modes.
// All methods return empty/false so callers never need nil checks.
type noopKMSProviderConfig struct{}

func (noopKMSProviderConfig) referencedSecretName() (string, []string, error) {
	return "", nil, fmt.Errorf("referencedSecretName called on non-KMS provider")
}
func (noopKMSProviderConfig) referencedConfigMapName() (string, []string, error) {
	return "", nil, fmt.Errorf("referencedConfigMapName called on non-KMS provider")
}
func (noopKMSProviderConfig) sameProviderInstance(configv1.KMSPluginConfig) (bool, error) {
	return false, fmt.Errorf("sameProviderInstance called on non-KMS provider")
}
func (noopKMSProviderConfig) sourceConfig() interface{} { return nil }

func newKMSProviderConfig(plugin configv1.KMSPluginConfig) (kmsProviderConfig, error) {
	switch plugin.Type {
	case configv1.VaultKMSProvider:
		return &vaultProviderConfig{plugin.Vault}, nil
	default:
		return nil, fmt.Errorf("unsupported KMS provider type %q", plugin.Type)
	}
}

type vaultProviderConfig struct {
	vault configv1.VaultKMSPluginConfig
}

func (v *vaultProviderConfig) sourceConfig() interface{} {
	return v.vault
}

func (v *vaultProviderConfig) referencedSecretName() (string, []string, error) {
	switch v.vault.Authentication.Type {
	case configv1.VaultAuthenticationTypeAppRole:
		// The Vault AppRole secret must contain "role-id" and "secret-id" keys.
		// These are the only keys carried into the encryption key secret.
		return v.vault.Authentication.AppRole.Secret.Name, []string{"role-id", "secret-id"}, nil
	default:
		return "", nil, fmt.Errorf("unsupported Vault authentication type %q", v.vault.Authentication.Type)
	}
}

func (v *vaultProviderConfig) referencedConfigMapName() (string, []string, error) {
	if v.vault.TLS.CABundle.Name == "" {
		return "", nil, nil
	}
	return v.vault.TLS.CABundle.Name, []string{"ca-bundle.crt"}, nil
}

func (v *vaultProviderConfig) sameProviderInstance(stored configv1.KMSPluginConfig) (bool, error) {
	if stored.Type != configv1.VaultKMSProvider {
		klog.V(2).Infof("KMS provider instance changed: provider type changed from %q to %q", stored.Type, configv1.VaultKMSProvider)
		return false, nil
	}
	if v.vault.VaultAddress != stored.Vault.VaultAddress {
		klog.V(2).Infof("KMS provider instance changed: VaultAddress changed from %q to %q", stored.Vault.VaultAddress, v.vault.VaultAddress)
		return false, nil
	}
	if v.vault.VaultNamespace != stored.Vault.VaultNamespace {
		klog.V(2).Infof("KMS provider instance changed: VaultNamespace changed from %q to %q", stored.Vault.VaultNamespace, v.vault.VaultNamespace)
		return false, nil
	}
	if v.vault.VaultKeyPath != stored.Vault.VaultKeyPath {
		klog.V(2).Infof("KMS provider instance changed: VaultKeyPath changed from %q to %q", stored.Vault.VaultKeyPath, v.vault.VaultKeyPath)
		return false, nil
	}
	return true, nil
}

// TODO make this un-settable once set
// ex: we could require the tech preview no upgrade flag to be set before we will honor this field
type unsupportedEncryptionConfig struct {
	Encryption struct {
		Reason string `json:"reason"`
	} `json:"encryption"`
}

// structuredUnsupportedConfigFrom returns unsupportedEncryptionConfig from the operator's observedConfig
func structuredUnsupportedConfigFrom(rawConfig []byte, prefix []string) (unsupportedEncryptionConfig, error) {
	if len(rawConfig) == 0 {
		return unsupportedEncryptionConfig{}, nil
	}

	unstructuredRawJSONCfg, err := unstructuredUnsupportedConfigFromWithPrefix(rawConfig, prefix)
	if err != nil {
		return unsupportedEncryptionConfig{}, err
	}

	encryptionConfig := unsupportedEncryptionConfig{}
	if err := json.Unmarshal(unstructuredRawJSONCfg, &encryptionConfig); err != nil {
		return unsupportedEncryptionConfig{}, err
	}

	return encryptionConfig, nil
}

// unstructuredUnsupportedConfigFrom returns the configuration from the operator's observedConfig field in the subtree given by the prefix
func unstructuredUnsupportedConfigFromWithPrefix(rawConfig []byte, prefix []string) ([]byte, error) {
	if len(prefix) == 0 {
		return rawConfig, nil
	}

	prefixedConfig := map[string]interface{}{}
	if err := json.NewDecoder(bytes.NewBuffer(rawConfig)).Decode(&prefixedConfig); err != nil {
		klog.V(4).Infof("decode of existing config failed with error: %v", err)
		return nil, err
	}

	actualConfig, _, err := unstructured.NestedFieldCopy(prefixedConfig, prefix...)
	if err != nil {
		return nil, err
	}

	return json.Marshal(actualConfig)
}
