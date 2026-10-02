package controllers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// EncryptionConfigurationComputer computes the encryption configuration secret
// passed to the KMS preflight deployer right before it creates a new deployment.
type EncryptionConfigurationComputer interface {
	ComputeEncryptionConfiguration(ctx context.Context, kmsPluginConfig *kms.KMSPluginConfig, generation int64) (*corev1.Secret, error)
}

// encryptionConfigurationComputer is the default EncryptionConfigurationComputer.
// It derives the encryption configuration the preflight workload should run with by applying
// the same key-planning and config-computation path as the key and state controllers.
type encryptionConfigurationComputer struct {
	instanceName             string
	unsupportedConfigPrefix  []string
	provider                 Provider
	encryptionDeployer       statemachine.Deployer
	secretsClient            corev1client.SecretsGetter
	configMapsClient         corev1client.ConfigMapsGetter
	apiServerClient          configv1client.APIServerInterface
	dynamicClient            dynamic.Interface
	operatorClient           operatorv1helpers.OperatorClient
	encryptionSecretSelector metav1.ListOptions
}

var _ EncryptionConfigurationComputer = (*encryptionConfigurationComputer)(nil)

func NewEncryptionConfigurationComputer(
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	secretsClient corev1client.SecretsGetter,
	configMapsClient corev1client.ConfigMapsGetter,
	apiServerClient configv1client.APIServerInterface,
	operatorClient operatorv1helpers.OperatorClient,
	dynamicClient dynamic.Interface,
	encryptionSecretSelector metav1.ListOptions,
) EncryptionConfigurationComputer {
	return &encryptionConfigurationComputer{
		instanceName:             instanceName,
		unsupportedConfigPrefix:  unsupportedConfigPrefix,
		provider:                 provider,
		encryptionDeployer:       encryptionDeployer,
		secretsClient:            secretsClient,
		configMapsClient:         configMapsClient,
		apiServerClient:          apiServerClient,
		dynamicClient:            dynamicClient,
		operatorClient:           operatorClient,
		encryptionSecretSelector: encryptionSecretSelector,
	}
}

func (c *encryptionConfigurationComputer) ComputeEncryptionConfiguration(ctx context.Context, kmsPluginConfig *kms.KMSPluginConfig, generation int64) (*corev1.Secret, error) {
	// ListKeysWhileProgressing=true so preflight can still list keys and compute a plan even when there
	// is no convergence yet. The key controller sets this to false to avoid extra Lists during rollout.
	planner := NewEncryptionPlanner(c.instanceName, c.unsupportedConfigPrefix, c.encryptionDeployer, c.secretsClient, c.configMapsClient, c.apiServerClient, c.operatorClient, c.dynamicClient, c.encryptionSecretSelector)
	var kmsOpt *KMSPluginConfig
	if kmsPluginConfig != nil {
		kmsOpt = &KMSPluginConfig{Config: kmsPluginConfig, Generation: generation}
	}
	snap, err := planner.Load(ctx, c.provider.EncryptedGRs(), LoadOptions{
		ListKeysWhileProgressing: true,
		KMSPluginConfig:          kmsOpt,
	})
	if err != nil {
		return nil, err
	}
	if snap.CurrentMode != "" && snap.CurrentMode != state.KMS {
		return nil, fmt.Errorf("preflight encryption config computation requires KMS mode, got %q", snap.CurrentMode)
	}

	plan, err := planner.PlanNextKey(snap)
	if err != nil {
		return nil, err
	}

	var plannedKey *PlannedEncryptionKey
	if plan.Needed {
		plannedKey, err = planner.MaterializeKey(ctx, snap, plan)
		if err != nil {
			return nil, err
		}
	} else {
		// No new key: in-place carry-over fields (image, TLS, auth, referenced data) may still
		// differ from the persisted write key. Project them into the snapshot so the preflight
		// pod validates the proposed config rather than the still-persisted one.
		if err := projectDesiredCarryOverForPreflight(ctx, c.instanceName, snap, plan.KeyID, c.secretsClient, c.configMapsClient); err != nil {
			return nil, err
		}
	}

	result, err := planner.ComputeConfig(&snap.State, plannedKey)
	if err != nil {
		return nil, err
	}
	if result.EncryptionSecret == nil {
		return nil, fmt.Errorf("no encryption key secrets available to compute preflight encryption config")
	}

	return result.EncryptionSecret, nil
}

// projectDesiredCarryOverForPreflight overlays the desired in-place carry-over fields
// (plugin config + referenced Secret/ConfigMap data) onto the write key in snap, then
// recomputes DesiredBeforePlan. Without this, ComputeConfig would build a preflight
// encryption config from the still-persisted key and a successful check of the old
// plugin could authorize an untested image/credential update (or revoked old credentials
// could block a valid replacement).
func projectDesiredCarryOverForPreflight(ctx context.Context, instanceName string, snap *KeyPlanningSnapshot, keyID uint64, secretClient corev1client.SecretsGetter, configMapClient corev1client.ConfigMapsGetter) error {
	if snap.CurrentMode != state.KMS || keyID == 0 {
		return nil
	}

	refSecret, refCM, err := fetchReferencedResources(ctx, snap.desiredProviderCfg, secretClient, configMapClient, openshiftConfigNS)
	if err != nil {
		return fmt.Errorf("failed to fetch referenced resources for preflight: %w", err)
	}
	desiredKMS, err := buildKMSCarryOverState(snap.PluginConfig, snap.desiredProviderCfg, refSecret, refCM)
	if err != nil {
		return fmt.Errorf("failed to build desired KMS carry-over state for preflight: %w", err)
	}

	for i, keySecret := range snap.State.KeySecrets {
		id, ok := state.NameToKeyID(keySecret.Name)
		if !ok || id != keyID {
			continue
		}
		ks, err := secrets.ToKeyState(keySecret)
		if err != nil {
			return fmt.Errorf("failed to parse key secret %s for preflight projection: %w", keySecret.Name, err)
		}
		if ks.KMS == nil {
			return fmt.Errorf("secret %s/%s is not a KMS key secret", keySecret.Namespace, keySecret.Name)
		}
		ks.KMS.Plugin = desiredKMS.Plugin
		ks.KMS.PluginSecretData = desiredKMS.PluginSecretData
		ks.KMS.PluginConfigMapData = desiredKMS.PluginConfigMapData
		updated, err := secrets.FromKeyState(instanceName, ks)
		if err != nil {
			return fmt.Errorf("failed to rebuild key secret %s for preflight projection: %w", keySecret.Name, err)
		}
		snap.State.KeySecrets[i] = updated
		snap.State.DesiredBeforePlan = statemachine.GetDesiredEncryptionState(snap.State.CurrentConfig, snap.State.KeySecrets, snap.State.EncryptedGRs)
		return nil
	}

	return fmt.Errorf("backing Secret for key %d missing from planning snapshot", keyID)
}
