package controllers

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	encryptionConfigManagedNS = "openshift-config-managed"
)

// EncryptionPlanner provides shared key planning and encryption-config computation for the key, state, and KMS preflight controllers without drift.
type EncryptionPlanner struct {
	instanceName             string
	unsupportedConfigPrefix  []string
	deployer                 statemachine.Deployer
	secretClient             corev1client.SecretsGetter
	configMapClient          corev1client.ConfigMapsGetter
	apiServerClient          configv1client.APIServerInterface
	operatorClient           operatorv1helpers.OperatorClient
	encryptionSecretSelector metav1.ListOptions
}

func NewEncryptionPlanner(instanceName string, unsupportedConfigPrefix []string, deployer statemachine.Deployer, secretClient corev1client.SecretsGetter, configMapClient corev1client.ConfigMapsGetter, apiServerClient configv1client.APIServerInterface, operatorClient operatorv1helpers.OperatorClient, encryptionSecretSelector metav1.ListOptions) *EncryptionPlanner {
	return &EncryptionPlanner{
		instanceName:             instanceName,
		unsupportedConfigPrefix:  unsupportedConfigPrefix,
		deployer:                 deployer,
		secretClient:             secretClient,
		configMapClient:          configMapClient,
		apiServerClient:          apiServerClient,
		operatorClient:           operatorClient,
		encryptionSecretSelector: encryptionSecretSelector,
	}
}

// EncryptionStateSnapshot is deployer convergence and persisted key secrets.
// Produced by LoadState. Input to ComputeConfig.
type EncryptionStateSnapshot struct {
	ProgressingReason string
	CurrentConfig     *encryptiondata.Config
	DesiredBeforePlan map[schema.GroupResource]state.GroupResourceState
	KeySecrets        []*corev1.Secret
	EncryptedGRs      []schema.GroupResource
}

// KeyPlanningSnapshot adds resolved encryption mode for key planning.
// Produced by Load. Required by PlanNextKey and MaterializeKey.
type KeyPlanningSnapshot struct {
	State              EncryptionStateSnapshot
	CurrentMode        state.Mode
	ExternalReason     string
	APIEncryption      configv1.APIServerEncryption
	desiredProviderCfg kmsProviderConfig
}

// KeyPlan is the deterministic result of deciding whether a new key is needed.
type KeyPlan struct {
	Needed         bool
	KeyID          uint64
	Reasons        []string
	InternalReason string
}

// PlannedEncryptionKey is a materialized in-memory key secret ready to persist or include in a candidate config.
type PlannedEncryptionKey struct {
	Secret  *corev1.Secret
	KeyID   uint64
	Reasons []string
}

// LoadOptions controls how Load reads key-planning state.
type LoadOptions struct {
	// ListKeysWhileProgressing lists persisted key secrets even when the
	// deployer has not converged. Default false so the key controller does
	// not List during API-server rollouts. Preflight sets this so PlanNextKey
	// can run. ProgressingReason is still populated in either case.
	ListKeysWhileProgressing bool
}

// EncryptionPlanResult is returned by ComputeConfig.
type EncryptionPlanResult struct {
	ProgressingReason string
	PlannedKey        *PlannedEncryptionKey
	CurrentConfig     *encryptiondata.Config
	DesiredState      map[schema.GroupResource]state.GroupResourceState
	EncryptionConfig  *encryptiondata.Config
	EncryptionSecret  *corev1.Secret
	KeySecrets        []*corev1.Secret
}

// plannedKeyBuildError marks failures while materializing an in-memory planned key (missing referenced Secrets/ConfigMaps, etc.). The key controller wraps these as "failed to create key" for historical degraded messages.
type plannedKeyBuildError struct {
	err error
}

func (e plannedKeyBuildError) Error() string { return e.err.Error() }
func (e plannedKeyBuildError) Unwrap() error { return e.err }

// LoadState reads deployer convergence and key secrets.
func (p *EncryptionPlanner) LoadState(ctx context.Context, encryptedGRs []schema.GroupResource) (*EncryptionStateSnapshot, error) {
	currentConfig, desiredBeforePlan, keySecrets, progressingReason, err := statemachine.GetEncryptionConfigAndState(ctx, p.deployer, p.secretClient, p.encryptionSecretSelector, encryptedGRs)
	if err != nil {
		return nil, err
	}
	return &EncryptionStateSnapshot{
		ProgressingReason: progressingReason,
		CurrentConfig:     currentConfig,
		DesiredBeforePlan: desiredBeforePlan,
		KeySecrets:        keySecrets,
		EncryptedGRs:      encryptedGRs,
	}, nil
}

// Load resolves encryption mode and reads deployer/key state for key planning.
// The returned snapshot is non-nil when err is nil.
func (p *EncryptionPlanner) Load(ctx context.Context, encryptedGRs []schema.GroupResource, opts LoadOptions) (*KeyPlanningSnapshot, error) {
	if p.apiServerClient == nil || p.operatorClient == nil {
		return nil, fmt.Errorf("Load requires apiServerClient and operatorClient")
	}

	// Resolve mode before reading deployer/key state so callers fail fast on APIServer/operator errors.
	currentMode, externalReason, apiEncryption, err := getCurrentModeReasonAndEncryptionConfig(ctx, p.apiServerClient, p.operatorClient, p.unsupportedConfigPrefix)
	if err != nil {
		return nil, err
	}

	stateSnap, err := p.LoadState(ctx, encryptedGRs)
	if err != nil {
		return nil, err
	}

	// LoadState calls GetEncryptionConfigAndState, which returns before listing keys when the deployer has not converged.
	// Preflight loads keys and desired state here via ListKeysWhileProgressing; the key controller skips this to avoid Lists during rollout.
	if len(stateSnap.ProgressingReason) > 0 && opts.ListKeysWhileProgressing {
		keySecrets, err := secrets.ListKeySecrets(ctx, p.secretClient, p.encryptionSecretSelector)
		if err != nil {
			return nil, err
		}
		stateSnap.KeySecrets = keySecrets
		stateSnap.DesiredBeforePlan = statemachine.GetDesiredEncryptionState(stateSnap.CurrentConfig, keySecrets, encryptedGRs)
	}

	snap := &KeyPlanningSnapshot{
		State:              *stateSnap,
		CurrentMode:        currentMode,
		ExternalReason:     externalReason,
		APIEncryption:      apiEncryption,
		desiredProviderCfg: noopKMSProviderConfig{},
	}

	if currentMode == state.KMS {
		desiredProviderCfg, err := newKMSProviderConfig(apiEncryption.KMS)
		if err != nil {
			return nil, err
		}
		snap.desiredProviderCfg = desiredProviderCfg
	}

	return snap, nil
}

// PlanNextKey deterministically decides whether a new key is needed. It does not generate key material.
func (p *EncryptionPlanner) PlanNextKey(snap *KeyPlanningSnapshot) (*KeyPlan, error) {
	if snap == nil {
		return nil, fmt.Errorf("snapshot is required")
	}

	hasBeenOnBefore := snap.State.CurrentConfig != nil || len(snap.State.KeySecrets) > 0
	if snap.CurrentMode == state.Identity && !hasBeenOnBefore {
		return &KeyPlan{}, nil
	}

	keyPlan, err := planNextEncryptionKey(snap.State.DesiredBeforePlan, snap.CurrentMode, snap.ExternalReason, snap.State.EncryptedGRs, snap.desiredProviderCfg)
	if err != nil {
		return nil, err
	}
	return &KeyPlan{
		Needed:         keyPlan.needed,
		KeyID:          keyPlan.keyID,
		Reasons:        keyPlan.reasons,
		InternalReason: keyPlan.internalReason,
	}, nil
}

// MaterializeKey builds an in-memory key secret for plan. Non-deterministic (fresh key bytes). Requires plan.Needed == true.
func (p *EncryptionPlanner) MaterializeKey(ctx context.Context, snap *KeyPlanningSnapshot, plan *KeyPlan) (*PlannedEncryptionKey, error) {
	if snap == nil {
		return nil, fmt.Errorf("snapshot is required")
	}
	if plan == nil || !plan.Needed {
		return nil, fmt.Errorf("MaterializeKey requires a needed key plan")
	}
	if p.configMapClient == nil {
		return nil, fmt.Errorf("configMapClient is required for MaterializeKey")
	}

	ks, _, _, err := buildEncryptionKeyState(ctx, plan.KeyID, snap.CurrentMode, snap.APIEncryption, snap.desiredProviderCfg, p.secretClient, p.configMapClient, plan.InternalReason, snap.ExternalReason)
	if err != nil {
		return nil, plannedKeyBuildError{err: err}
	}
	keySecret, err := secrets.FromKeyState(p.instanceName, ks)
	if err != nil {
		return nil, plannedKeyBuildError{err: err}
	}
	return &PlannedEncryptionKey{
		Secret:  keySecret,
		KeyID:   plan.KeyID,
		Reasons: plan.Reasons,
	}, nil
}

// ComputeConfig builds the desired encryption-config secret from persisted keys, optionally including plannedKey.
// When plannedKey is nil it reuses DesiredBeforePlan instead of recomputing desired state.
func (p *EncryptionPlanner) ComputeConfig(state *EncryptionStateSnapshot, plannedKey *PlannedEncryptionKey) (*EncryptionPlanResult, error) {
	if state == nil {
		return nil, fmt.Errorf("snapshot is required")
	}

	keySecrets := state.KeySecrets
	if plannedKey != nil && plannedKey.Secret != nil {
		keySecrets = append(append([]*corev1.Secret{}, state.KeySecrets...), plannedKey.Secret)
	}

	out := &EncryptionPlanResult{
		CurrentConfig: state.CurrentConfig,
		KeySecrets:    keySecrets,
		PlannedKey:    plannedKey,
	}

	if state.CurrentConfig == nil && len(keySecrets) == 0 {
		return out, nil
	}

	// DesiredBeforePlan already reflects persisted keys. Recompute only when a planned key was appended
	out.DesiredState = state.DesiredBeforePlan
	if plannedKey != nil && plannedKey.Secret != nil {
		out.DesiredState = statemachine.GetDesiredEncryptionState(state.CurrentConfig, keySecrets, state.EncryptedGRs)
	}

	cfg, err := encryptiondata.FromEncryptionState(out.DesiredState)
	if err != nil {
		return nil, fmt.Errorf("failed to build encryption config: %w", err)
	}
	out.EncryptionConfig = cfg

	secretName := fmt.Sprintf("%s-%s", encryptiondata.EncryptionConfSecretName, p.instanceName)
	secret, err := encryptiondata.ToSecret(encryptionConfigManagedNS, secretName, cfg)
	if err != nil {
		return nil, err
	}
	out.EncryptionSecret = secret

	return out, nil
}
